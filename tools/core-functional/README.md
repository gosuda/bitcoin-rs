# Core functional compatibility lane

Runs Bitcoin Core v31.1's Python functional test suite (`test/functional`)
against the bitcoin-rs node binary, without modifying either side: the suite
is extracted from a pinned Core tag into the gitignored scratch area, and the
node is presented to the framework through an argv/config/cookie adapter that
the framework spawns instead of `bitcoind`.

Everything in this directory is external validation tooling. Nothing here
changes consensus, persistence, or node behavior; the node is only invoked.

## Status

Measured baseline exists; see [Measured results](#measured-results) below.
The first full run against a built bitcoin-rs binary completed on 2026-10-30:
4 of the 46 selected candidates passed, 5 skipped by the framework's own
gating, 37 failed - every failure triaged to a node-side gap, itemized below.
A second measured run (same day, after node-side fixes for NG-1/NG-2/NG-15 and
the accounting half of NG-5) reproduced 4/5/37 with one failure-point movement;
see [Run 2](#run-2-post-ng-1215-and-ng-5-accounting-half-fixes-ng-16-isolated)
below. A third measured run (same day,
after the ping-origination fix for NG-16) again reproduced 4/5/37 while all
six pong-wait tests moved past `connect_nodes` into their bodies; see
[Run 3](#run-3-post-ng-16-ping-origination) below. A fourth measured run (same
day, after the NG-17 named-params bindings, the NG-9 `uacomment` option, and
the NG-8 fully-silent console level) measured 8/5/33 - the lane's first status
movements: four tests PASS; see
[Run 4](#run-4-post-ng-1798-fixes) below. A fifth run re-anchored the record
on the PR-stack tree with a byte-identical binary and the same 8/5/33; see
[Run 5](#run-5-pr-stack-anchor) below. After the stack was rebased onto main
(main's node code had moved, so binary identity no longer held), a sixth
execution re-anchored the record on the rebased tree with a new binary
identity and the same 8/5/33 and per-test statuses; see
[Run 5b](#run-5b-post-rebase-re-anchor) below. Run 5b predates the
post-review node commits landed on PRs 2 and 3 after it; those commits are
unmeasured and named in the run-5b note rather than silently covered. The
runs' `report.json`/`report.md` under `target/core-functional/results/` are
the evidence owners.
No claim beyond the 46 selected candidates is made; nothing here extrapolates
to Core's full 262-script suite.

Known expectation, now measured rather than assumed: tests whose setup
depends on Core-only flags the adapter drops (`-loadblock=`, `-includeconf=`,
`-blocksdir`, `-startupnotify`, net permission flags, the
Core-format blocks directory) fail honestly on the node's missing
equivalents, with the dropped token recorded in the per-datadir
`wrapper-dropped-flags.log`. (`-uacomment=` was translated instead of dropped
for run 4.)

## Measured results

### Landing map

The campaign that produced these runs landed as a four-PR stack referencing
issue #1757: `core-functional-tools` (PR 1, lane infra) →
`core-functional-p2p` (PR 2, node fixes) → `core-functional-rpc` (PR 3, node
fixes) → `core-functional-evidence` (PR 4, this record). Where each run
landed:

| run | campaign commit carrying its record | landed as |
|-----|--------------------------------------|-----------|
| run 1 | `9b1d46054` | record + gap ledger here (PR 4); the adapter/infra half of the commit is squashed into PR 1 (`core-functional-tools`); the `stop` fix its binary carried (`7913be736`) is PR 3's first commit |
| run 2 | `8cf52b93c` | record here (PR 4); the `862068637` fixes it measured (params-object forms, `syncwithvalidationinterfacequeue`, `--version`, shim sync) are PR 3; the `cb9cf472c` byte accounting is PR 2 |
| run 3 | `1f51eb4ab` | record here (PR 4); the `e18b2ade2` ping origination it measured is PR 2 |
| run 4 | `7aff3c5d4` | record here (PR 4); the uacomment / named-params / silent-console fixes it measured (then uncommitted, `a32b3856e`) are PR 3's tip |
| run 5 | this record (pre-rebase) | pre-rebase stack anchor; superseded by run 5b after the review rebase onto main |
| run 5b | this record | re-anchor on the rebased stack (binary `50131c6a...`, same 8/5/33 and failure points as run 4) |

The node binary is built from `bin/` and `crates/` only - `tools/` is outside
the build - so regrouping the tools-side commits between branches cannot
change binary identity; run 5 below re-measures this stack's tree to anchor
that. The per-run campaign commits (including the per-run README deltas this
record replaces) live on the local-only `core-functional-compat` and
`core-functional-compat-backup` archive branches, which are not pushed to
the remote; every `sha` cited below is one of those local archive commits.
Where such a commit carried node code, its content landed in the stack as:

| campaign hash | landed commit | where |
|---------------|---------------|-------|
| `7913be736` | `a719b9223` | PR 3 (`stop` RPC) |
| `862068637` | `aca495e5a` | PR 3 (named params, `syncwithvalidationinterfacequeue`, `--version`, shim sync) |
| `a32b3856e` | `68f61a3a7` | PR 3 (uacomment / named params / silent console) |
| `cb9cf472c` | `f492559a7` | PR 2 (getpeerinfo per-message byte accounting) |
| `e18b2ade2` | `cbcfd5489` | PR 2 (ping origination) |

First measured run: **2026-10-30**, on the local `core-functional-compat` branch.

- bitcoin-rs commit: `02dc034c936a5c184b4313c4972b04703af30eb1` (includes the
  `stop` RPC from `7913be736`)
- build: `cargo build --locked -p bitcoin-rs --profile quickstart --no-default-features --features fjall`
  (binary sha256 `b571a12910f8446a1d0ca431bf77902aa2bea3610cba8107d711ab908f3aae76`); rest/txindex/blockfilterindex are runtime
  flags, not compile gates; zmq and usdt tracepoints are covered by the
  framework's own skip paths (`ENABLE_ZMQ=false`, `ENABLE_USDT_TRACEPOINTS=false`)
- Core suite: v31.1 (`9be056a8a72b624dae9623b2f7bded92c2a21c91`) extracted from
  `/home/deploy/git/bitcoin`
- runner: `tools/core-functional/run.sh --jobs 6 --timeout 300`, evidence in
  `target/core-functional/results/final/` (`report.json`, per-test `tmp/`)
- chain cache: built once beforehand by the lane's own binary
  (`results/cachebuild4/`): 199 regtest blocks via `generatetoaddress` in 8
  batches, `stop` teardown, then the framework's `copytree` propagated the
  node's own storage (`bitcoin-rs-data/`) to every node datadir; seeded into
  the final run's cachedir. This succeeded - the premine path
  (`setmocktime`-no-op -> `getbestblockhash` -> `getblockheader` ->
  `generatetoaddress` x199 -> `getblockchaininfo == 199` -> `stop`) works.
- shim patches ACTIVE during the run (see `shim/sitecustomize.py` header;
  each is a disclosed adaptation around a node gap; the RPC no-op and
  stop-wait patches are disable-able via env var, the MiniWallet
  `generatetoaddress` patch is unconditional, raw failures preserved in
  `results/raw-evidence*/`)

**4 of the 46 selected candidates passed** (4 pass / 5 skip / 37 fail).
Every failure is a node-side gap; no infra or harness-host failures remained
in the final run. Cause classes: `NG-n` = node gap numbered below.

| test | status | cause | one-line cause |
|------|--------|-------|----------------|
| feature_discover | PASS | | |
| mining_mainnet | PASS | | |
| rpc_decodescript | PASS | | |
| rpc_deprecated | PASS | | |
| example_test | SKIP | framework | wallet not compiled (ENABLE_WALLET=false) |
| feature_bind_port_discover | SKIP | framework | needs routable 1.1.1.1/2.2.2.2 on host interfaces |
| feature_bind_port_externalip | SKIP | framework | needs routable 1.1.1.1 on a host interface |
| interface_usdt_net | SKIP | framework | USDT tracepoints disabled in config.ini |
| interface_usdt_validation | SKIP | framework | USDT tracepoints disabled in config.ini |
| feature_bind_extra | FAIL | NG-12 | `-bind=IP:PORT=onion` dropped (no equivalent); node listens on conf port instead (`{0.0.0.0:13161}` vs expected `{127.0.0.1:13164}`) |
| feature_blocksdir | FAIL | NG-7 | `blocks_path` `<datadir>/regtest/blocks` never created; `-blocksdir` dropped |
| feature_chain_tiebreaks | FAIL | NG-6 | test reads `<datadir>/regtest/debug.log`: no debug log file at Core's path |
| feature_dirsymlinks | FAIL | NG-7 | manipulates `<datadir>/regtest/blocks` as a symlink: no Core-format blocks dir |
| feature_framework_startup_failures | FAIL | NG-14 | node starts successfully on conf/flags Core refuses at startup ("Should have failed earlier during startup") |
| feature_help | FAIL | NG-15 | `-h` leg passes; `-version` leg: binary has no `--version` flag (clap exit 2, expected 0) |
| feature_includeconf | FAIL | NG-9 | `-includeconf` dropped; subversion lacks the includeconf-derived uacomment (`...main; relative)/`) |
| feature_loadblock | FAIL | NG-5 | multi-node setup dies in `connect_nodes` pong wait before `-loadblock` (itself dropped, NG-7) |
| feature_posix_fs_permissions | FAIL | NG-6 | datadir+wallets perm checks pass (wrapper-created 0700); fails on missing `<datadir>/regtest/debug.log` |
| feature_presegwit_node_upgrade | FAIL | NG-13 | `softfork_active(node,"segwit")` true where the test expects false (deployment reporting) |
| feature_proxy | FAIL | NG-12 | proxied peer never appears in `getpeerinfo` (proxy peer visibility) |
| feature_reindex_init | FAIL | NG-7 | test corrupts Core-format `regtest/blocks/index` (absent); `-test=reindex_*` flag dropped |
| feature_remove_pruned_files_on_startup | FAIL | NG-7 | expects Core-format `regtest/blocks/blk00000.dat` pruning layout |
| feature_shutdown | FAIL | NG-4 | `stop(wait=1000)`: node refuses any stop argument (registry-documented deviation) with `-32602` |
| feature_startupnotify | FAIL | NG-12 | `-startupnotify` dropped (no equivalent); notify file never created |
| feature_uacomment | FAIL | NG-9 | `-uacomment` dropped; subversion `...n-rs:0.14.0` lacks `testnode0` |
| feature_versionbits_warning | FAIL | NG-8/NG-12 | no versionbits warning; node's own WARN stderr output breaks the exact-stderr teardown assertion |
| interface_http | FAIL | NG-11 | RPC HTTP server closes the connection after the reply (no keep-alive); `conn.sock is not None` fails |
| interface_rpc | FAIL | NG-6 | `getrpcinfo.logpath` = `<data-dir>/debug.log` (file never written) vs Core's `<datadir>/<chain>/debug.log` |
| p2p_add_connections | FAIL | NG-12 | p2p `wait_until` (is_connected) after adding connections |
| p2p_block_sync | FAIL | NG-5 | `connect_nodes` pong wait (`bytesrecv_per_msg.pong >= 29` never observed) |
| p2p_compactblocks_blocksonly | FAIL | NG-12 | node sends 2 `sendcmpct` where 1 expected (compact-blocks announce count) |
| p2p_compactblocks_hb | FAIL | NG-5 | `connect_nodes` pong wait |
| p2p_getdata | FAIL | NG-12 | p2p `wait_until` after getdata handshake probes |
| p2p_invalid_locator | FAIL | NG-8 | protocol logic passes (101/102 locator behavior matches); teardown fails on WARN stderr lines (`p2p inbound handshake failed...`) where empty stderr expected |
| p2p_message_capture | FAIL | NG-12 | `-capture` message capture unsupported; no `msgs_recv.dat` written |
| p2p_net_deadlock | FAIL | NG-5 | `connect_nodes` pong wait |
| p2p_nobloomfilter_messages | FAIL | NG-12 | p2p `wait_until` (bloom-filter negotiation expectations) |
| p2p_v2_encrypted | FAIL | NG-12 | nodes start (after wrapper last-wins fix); v2 transport handshake wait times out |
| rpc_bind | FAIL | NG-12 | rpc listen set lacks `::1` (IPv6) listener: `{127.0.0.1}` vs `{127.0.0.1, ::1}` |
| rpc_deriveaddresses | FAIL | NG-10 | error text: `key with hardened derivation steps cannot be a DerivedDescriptorKey` vs Core `Cannot derive script without private keys` |
| rpc_estimatefee | FAIL | NG-10 | error text: `invalid params: conf_target is required` vs Core's `estimatesmartfee ...` message |
| rpc_getblockfilter | FAIL | NG-5 | `connect_nodes` pong wait (blockfilterindex leg never reached) |
| rpc_getchaintips | FAIL | NG-5 | `connect_nodes` pong wait |
| rpc_getdescriptorinfo | FAIL | NG-10 | error text: `invalid params: descriptor is required` vs expected substring `getdescriptorinfo` |
| rpc_validateaddress | FAIL | NG-10 | invalid-address result omits `error`/`error_locations` fields Core returns |
| rpc_whitelist | FAIL | NG-11 | unauthorized RPC answered HTTP 403 where Core answers 401 (`rpcwhitelist*` flags also dropped) |

### Run 2 (post NG-1/2/15 and NG-5 accounting-half fixes; NG-16 isolated)

Second measured run: **2026-10-30**, same branch, with the NG-1/NG-2/NG-15
fixes and NG-5's per-message accounting half in the tree; this run then
isolated NG-5's residual blocker (no originated ping) and renumbered it
**NG-16**:

- bitcoin-rs commit: `8620686378348610882bdda47577a08efcecfe0e`
  (`cb9cf472c` getpeerinfo per-message byte accounting on top of run 1's
  `02dc034c9`; `862068637` empty-object/named params, `syncwithvalidationinterfacequeue`, `--version`)
- build: same profile as run 1
  (binary sha256 `44e4e4a83729d96e4501c65d7f6e86fe5a2b50e67e2e3d4e0a4efd5ef227a08f`)
- runner: `tools/core-functional/run.sh --jobs 6 --timeout 300 --results-dir target/core-functional/results/run2`
  (190.6s wall); chain cache **reused** - run 1's 199-block `results/final/cache`
  was seeded into `results/run2/cache` beforehand, and no test rebuilt it
- shim patches ACTIVE: the three remaining pieces (MiniWallet
  `generatetoaddress` retarget, `setmocktime` client no-op [NG-3], `stop(wait=0)`
  strip [NG-4]); the run-1 params-rewrite and sync-no-op patches stayed deleted
- closed-gap probes (direct, single fresh node): `params:{}` accepted for
  zero-arg methods; `generatetoaddress(nblocks=,address=)` named-object form
  binds; `syncwithvalidationinterfacequeue` answers `null`; `--version` exits 0
  with version text. `setmocktime` still answers `-32601` (NG-3 open; shim
  patch 2 still required). Raw outputs: `results/run2/gap-probes.md`.

**4 of the 46 selected candidates passed** (4 pass / 5 skip / 37 fail) - the
same tests as run 1, with **zero status changes** and exactly one
failure-point movement:

- `feature_help` moved: its `-h` and `-version` legs now pass (NG-15 closed),
  and it fails one leg later, on `-fakearg` - Core exits 1 on an unknown CLI
  flag; the wrapper drops the flag and the node starts and keeps running, so
  `process.wait(timeout=60)` expires. Reclassified NG-15 -> NG-14 (whose argv
  half this run exposed precisely: the node itself exits 2 on unknown flags
  when invoked directly; the wrapper's drop converts that into a silent
  successful start).
- The expected progression of multi-node tests past `connect_nodes` did **not**
  materialize. All six pong-wait tests fail at byte-identical failure points
  to run 1: run 1's NG-5 named "pong size/cadence or per-message accounting"
  as the suspect - the accounting half is now fixed and measurable (handshake
  frames show up per-message with real wire sizes), but a controlled two-node
  experiment (see `results/run2/gap-probes.md`) shows neither node ever
  **originates a ping** after the version handshake, so no pong is ever
  received and `bytesrecv_per_msg['pong']` stays 0. Core sends its first ping
  immediately after the handshake (v31.1 `MaybeSendPing`,
  `net_processing.cpp:5718`: `m_ping_start` initializes to the clock epoch, so
  `now > m_ping_start + PING_INTERVAL` is true on the first pass). That
  residual - previously indistinguishable from the accounting gap - is now
  numbered **NG-16** below; NG-16 subsumes NG-5's remaining scope, so the
  ledger records NG-5 as accounting-half closed, not fully closed.
- Every other FAIL is unchanged in cause class and failure origin (verified by
  exact predicate/exception/traceback-origin comparison against run 1's logs;
  differences are only ephemeral ports, timestamps, and results-dir paths).
- No INFRA or TEST-ENV failures; no wrapper/runner/shim changes were needed.
- Note: the phase brief expected `rpc_uptime` to still fail on NG-3, but it is
  not one of the 46 selected candidates (see `tests/clean-candidates.txt`);
  nothing was run for it. NG-3 stays open on the probe evidence above.

| test | status | cause | delta vs run 1 | one-line cause |
|------|--------|-------|----------------|----------------|
| feature_discover | PASS | | = | |
| mining_mainnet | PASS | | = | |
| rpc_decodescript | PASS | | = | |
| rpc_deprecated | PASS | | = | |
| example_test | SKIP | framework | = | wallet not compiled (ENABLE_WALLET=false) |
| feature_bind_port_discover | SKIP | framework | = | needs routable 1.1.1.1/2.2.2.2 on host interfaces |
| feature_bind_port_externalip | SKIP | framework | = | needs routable 1.1.1.1 on a host interface |
| interface_usdt_net | SKIP | framework | = | USDT tracepoints disabled in config.ini |
| interface_usdt_validation | SKIP | framework | = | USDT tracepoints disabled in config.ini |
| feature_bind_extra | FAIL | NG-12 | = | `-bind=IP:PORT=onion` dropped; node listens on conf port instead (`{0.0.0.0:11684}` vs expected `{127.0.0.1:11687}`) |
| feature_blocksdir | FAIL | NG-7 | = | `blocks_path` `<datadir>/regtest/blocks` never created; `-blocksdir` dropped |
| feature_chain_tiebreaks | FAIL | NG-6 | = | test reads `<datadir>/regtest/debug.log`: no debug log file at Core's path |
| feature_dirsymlinks | FAIL | NG-7 | = | manipulates `<datadir>/regtest/blocks` as a symlink: no Core-format blocks dir |
| feature_framework_startup_failures | FAIL | NG-14 | = | node starts successfully on conf/flags Core refuses at startup ("Should have failed earlier during startup") |
| feature_help | FAIL | NG-14 | moved | `-h` and `-version` legs now PASS (NG-15 closed); `-fakearg` leg: Core exits 1, wrapper drops the flag, node runs -> `wait(60)` expires |
| feature_includeconf | FAIL | NG-9 | = | `-includeconf` dropped; subversion lacks the includeconf-derived uacomment |
| feature_loadblock | FAIL | NG-16 | = point | `connect_nodes` pong wait (no originated ping; `-loadblock` itself also dropped, NG-7) |
| feature_posix_fs_permissions | FAIL | NG-6 | = | datadir+wallets perm checks pass; fails on missing `<datadir>/regtest/debug.log` |
| feature_presegwit_node_upgrade | FAIL | NG-13 | = | `softfork_active(node,"segwit")` true where the test expects false (deployment reporting) |
| feature_proxy | FAIL | NG-12 | = | proxied peer never appears in `getpeerinfo` (fails before the pong wait) |
| feature_reindex_init | FAIL | NG-7 | = | test corrupts Core-format `regtest/blocks/index` (absent); `-test=reindex_*` flag dropped |
| feature_remove_pruned_files_on_startup | FAIL | NG-7 | = | expects Core-format `regtest/blocks/blk00000.dat` pruning layout |
| feature_shutdown | FAIL | NG-4 | = | `stop(wait=1000)`: node refuses any stop argument (registry-documented deviation) with `-32602` (byte-identical to run 1) |
| feature_startupnotify | FAIL | NG-12 | = | `-startupnotify` dropped; notify file never created (`tmpdir_file.exists()` wait; single-node test, no `connect_nodes` involved) |
| feature_uacomment | FAIL | NG-9 | = | `-uacomment` dropped; subversion `...n-rs:0.14.0` lacks `testnode0` |
| feature_versionbits_warning | FAIL | NG-8/NG-12 | = | no versionbits warning; node's own WARN stderr output breaks the exact-stderr teardown assertion |
| interface_http | FAIL | NG-11 | = | RPC HTTP server closes the connection after the reply (no keep-alive); `conn.sock is not None` fails |
| interface_rpc | FAIL | NG-6 | = | `getrpcinfo.logpath` = `<data-dir>/debug.log` (file never written) vs Core's `<datadir>/<chain>/debug.log` |
| p2p_add_connections | FAIL | NG-12 | = | `add_outbound_p2p_connection` `wait_for_connect` times out (p2p_idx 0..3 loop, node never dials the configured outbound slot) |
| p2p_block_sync | FAIL | NG-16 | = point | `connect_nodes` pong wait (`bytesrecv_per_msg.pong >= 29` never observed - no originated ping) |
| p2p_compactblocks_blocksonly | FAIL | NG-12 | = | node sends 2 `sendcmpct` where 1 expected (compact-blocks announce count) |
| p2p_compactblocks_hb | FAIL | NG-16 | = point | `connect_nodes` pong wait |
| p2p_getdata | FAIL | NG-12 | = | p2p `wait_until` (`blocks[best_block] == 1`) after getdata handshake probes |
| p2p_invalid_locator | FAIL | NG-8 | = | protocol logic passes; teardown fails on WARN stderr lines where empty stderr expected |
| p2p_message_capture | FAIL | NG-12 | = | `-capture` message capture unsupported; no `msgs_recv.dat` written (IndexError on empty capture list) |
| p2p_net_deadlock | FAIL | NG-16 | = point | `connect_nodes` pong wait |
| p2p_nobloomfilter_messages | FAIL | NG-12 | = | p2p `wait_for_disconnect` after `msg_mempool` (bloom-filter negotiation expectations) |
| p2p_v2_encrypted | FAIL | NG-12 | = | v2-transport handshake wait (`add_outbound_p2p_connection(supports_v2_p2p=False)` leg) |
| rpc_bind | FAIL | NG-12 | = | rpc listen set lacks `::1` (IPv6) listener: `{127.0.0.1:20822}` vs `{127.0.0.1:20822, [::1]:20822}` |
| rpc_deriveaddresses | FAIL | NG-10 | = | error text: `key with hardened derivation steps cannot be a DerivedDescriptorKey` vs Core `Cannot derive script without private keys` |
| rpc_estimatefee | FAIL | NG-10 | = | error text: `invalid params: conf_target is required` vs Core's `estimatesmartfee ...` message |
| rpc_getblockfilter | FAIL | NG-16 | = point | `connect_nodes` pong wait (blockfilterindex leg never reached) |
| rpc_getchaintips | FAIL | NG-16 | = point | `connect_nodes` pong wait |
| rpc_getdescriptorinfo | FAIL | NG-10 | = | error text: `invalid params: descriptor is required` vs expected substring `getdescriptorinfo` |
| rpc_validateaddress | FAIL | NG-10 | = | invalid-address result omits `error`/`error_locations` fields Core returns |
| rpc_whitelist | FAIL | NG-11 | = | unauthorized RPC answered HTTP 403 where Core answers 401 (`rpcwhitelist*` flags also dropped) |


### Run 3 (post NG-16 ping origination)

Third measured run: **2026-10-30**, same branch, after the node learned to
originate pings (NG-16 fix; `crates/p2p` `Keepalive::decide` now owes the
first probe on the first message-loop pass after the handshake, matching
Core 31.1's epoch-initialized `m_ping_start`, then the existing 2-minute
idle-gated cadence; both connection directions).

- bitcoin-rs commit: `e18b2ade2` (run 3 measured the byte-identical
  working tree one commit earlier at `8cf52b93c` + the ping change; the
  built binary is the identity below)
- build: same profile as runs 1-2
  (binary sha256 `800aa9739cb7153f303bf00930887f6e220c76b41ec3590d3b9f69b5bff7c10d`)
- runner: `tools/core-functional/run.sh --jobs 6 --timeout 300 --results-dir target/core-functional/results/run3`
  (140.9s wall); chain cache **reused** - run 2's `results/run2/cache` was
  seeded into `results/run3/cache` beforehand (same 199-block chain), and no
  test rebuilt it
- shim patches: the same three as run 2, unchanged; no wrapper/runner/shim
  changes were needed
- NG-16 closure verified directly (see `results/run3/gap-probes.md`): the
  two-node experiment that showed zero pings for 50s in run 2 now shows
  `ping: 29` sent and `pong: 29` received on BOTH sides within 1s of
  `addnode onetry`, and no second ping inside 30s (2-minute cadence held).

**4 of the 46 selected candidates passed** (4 pass / 5 skip / 37 fail) - the
same tests as runs 1-2, zero status changes, but **all six NG-16 tests moved
past `connect_nodes` into their bodies** and now fail on deeper gaps. Two new
gaps numbered: NG-17 (named-object params rejected for non-zero-arg RPCs) and
NG-18 (`generatetoaddress` hard-fails `-32603` on a submit-time stale parent).
One pre-existing-but-newly-reached failure mode: the node's WARN-on-disconnect
stderr line (NG-8) now breaks teardown for tests whose peer sockets first
exist because `connect_nodes` completes.

| test | status | cause | delta vs run 2 | one-line cause |
|------|--------|-------|----------------|----------------|
| feature_discover | PASS | | = | |
| mining_mainnet | PASS | | = | |
| rpc_decodescript | PASS | | = | |
| rpc_deprecated | PASS | | = | |
| example_test | SKIP | framework | = | wallet not compiled (ENABLE_WALLET=false) |
| feature_bind_port_discover | SKIP | framework | = | needs routable 1.1.1.1/2.2.2.2 on host interfaces |
| feature_bind_port_externalip | SKIP | framework | = | needs routable 1.1.1.1 on a host interface |
| interface_usdt_net | SKIP | framework | = | USDT tracepoints disabled in config.ini |
| interface_usdt_validation | SKIP | framework | = | USDT tracepoints disabled in config.ini |
| feature_bind_extra | FAIL | NG-12 | = | `-bind=IP:PORT=onion` dropped; node listens on conf port instead (`{0.0.0.0:15856}` vs expected `{127.0.0.1:15859}`) |
| feature_blocksdir | FAIL | NG-7 | = | `blocks_path` `<datadir>/regtest/blocks` never created; `-blocksdir` dropped |
| feature_chain_tiebreaks | FAIL | NG-6 | = | test reads `<datadir>/regtest/debug.log`: no debug log file at Core's path |
| feature_dirsymlinks | FAIL | NG-7 | = | manipulates `<datadir>/regtest/blocks` as a symlink: no Core-format blocks dir |
| feature_framework_startup_failures | FAIL | NG-14 | = | node starts successfully on conf/flags Core refuses at startup ("Should have failed earlier during startup") |
| feature_help | FAIL | NG-14 | = | `-fakearg` leg: Core exits 1, wrapper drops the flag, node runs -> `wait(60)` expires |
| feature_includeconf | FAIL | NG-9 | = | `-includeconf` dropped; subversion lacks the includeconf-derived uacomment |
| feature_loadblock | FAIL | NG-17 | moved | `connect_nodes` now passes; `setnetworkactive(state=False)` (named-object params) answered `-32602 params must be an array` (`-loadblock` itself still NG-7, behind this) |
| feature_posix_fs_permissions | FAIL | NG-6 | = | datadir+wallets perm checks pass; fails on missing `<datadir>/regtest/debug.log` |
| feature_presegwit_node_upgrade | FAIL | NG-13 | = | `softfork_active(node,"segwit")` true where the test expects false (deployment reporting) |
| feature_proxy | FAIL | NG-12 | = | proxied peer never appears in `getpeerinfo` (fails before the pong wait) |
| feature_reindex_init | FAIL | NG-7 | = | test corrupts Core-format `regtest/blocks/index` (absent); `-test=reindex_*` flag dropped |
| feature_remove_pruned_files_on_startup | FAIL | NG-7 | = | expects Core-format `regtest/blocks/blk00000.dat` pruning layout |
| feature_shutdown | FAIL | NG-4 | = | `stop(wait=1000)`: node refuses any stop argument (registry-documented deviation) with `-32602` |
| feature_startupnotify | FAIL | NG-12 | = | `-startupnotify` dropped; notify file never created (single-node test, no `connect_nodes` involved) |
| feature_uacomment | FAIL | NG-9 | = | `-uacomment` dropped; subversion `...n-rs:0.14.0` lacks `testnode0` |
| feature_versionbits_warning | FAIL | NG-18 | moved | fails earlier, at `generatetoaddress` after `send_blocks_with_version`: `-32603 generated block was not accepted: Rejected("inconclusive-not-best-prevblk")` (submit-time stale parent; run 2's body passed the same calls - race, single execution per candidate; NG-8/NG-12 legs now behind this) |
| interface_http | FAIL | NG-11 | = | RPC HTTP server closes the connection after the reply (no keep-alive); `conn.sock is not None` fails |
| interface_rpc | FAIL | NG-6 | = | `getrpcinfo.logpath` = `<data-dir>/debug.log` (file never written) vs Core's `<datadir>/<chain>/debug.log` |
| p2p_add_connections | FAIL | NG-12 | = | `add_outbound_p2p_connection` `wait_for_connect` times out (node never dials the configured outbound slot) |
| p2p_block_sync | FAIL | NG-8 | moved | body passes (`Success!`); teardown exact-stderr fails on node WARN `p2p peer disconnected with error ... unexpected end of file` (peer sockets first exist at stop now that `connect_nodes` completes) |
| p2p_compactblocks_blocksonly | FAIL | NG-12 | = | node sends 2 `sendcmpct` where 1 expected (compact-blocks announce count) |
| p2p_compactblocks_hb | FAIL | NG-9 | moved | `connect_nodes` passes; the later `connect_nodes(peer, 0)` waits out on a stale inbound because `disconnect_nodes` no-ops (subver lacks `testnode{n}`; dropped `-uacomment`) |
| p2p_getdata | FAIL | NG-12 | = | p2p `wait_until` (`blocks[best_block] == 1`) after getdata handshake probes |
| p2p_invalid_locator | FAIL | NG-8 | = | protocol logic passes; teardown fails on WARN stderr lines where empty stderr expected |
| p2p_message_capture | FAIL | NG-12 | = | `-capture` message capture unsupported; no `msgs_recv.dat` written (IndexError on empty capture list) |
| p2p_net_deadlock | FAIL | NG-8 | moved | body passes (no deadlock); teardown exact-stderr fails on the same WARN disconnect line as `p2p_block_sync` |
| p2p_nobloomfilter_messages | FAIL | NG-12 | = | p2p `wait_for_disconnect` after `msg_mempool` (bloom-filter negotiation expectations) |
| p2p_v2_encrypted | FAIL | NG-12 | = | v2-transport handshake wait (`add_outbound_p2p_connection(supports_v2_p2p=False)` leg) |
| rpc_bind | FAIL | NG-12 | = | rpc listen set lacks `::1` (IPv6) listener: `{127.0.0.1:16533}` vs `{127.0.0.1:16533, [::1]:16533}` |
| rpc_deriveaddresses | FAIL | NG-10 | = | error text: `key with hardened derivation steps cannot be a DerivedDescriptorKey` vs Core `Cannot derive script without private keys` |
| rpc_estimatefee | FAIL | NG-10 | = | error text: `invalid params: conf_target is required` vs Core's `estimatesmartfee ...` message |
| rpc_getblockfilter | FAIL | NG-9 | moved | `connect_nodes` passes; `disconnect_nodes(0,1)` no-ops (subver lacks `testnode{n}`), so node0/node1 `generate` calls overlap on one chain and node1's hits `-32603 inconclusive-not-best-prevblk` (NG-18 mechanism; see gap-probes) |
| rpc_getchaintips | FAIL | NG-9 | moved | `connect_nodes` passes; `split_network`'s `disconnect_nodes` no-ops, node1 receives both halves' blocks: `not(230 == 210)` at `shortTip['height']` |
| rpc_getdescriptorinfo | FAIL | NG-10 | = | error text: `invalid params: descriptor is required` vs expected substring `getdescriptorinfo` |
| rpc_validateaddress | FAIL | NG-10 | = | invalid-address result omits `error`/`error_locations` fields Core returns |
| rpc_whitelist | FAIL | NG-11 | = | unauthorized RPC answered HTTP 403 where Core answers 401 (`rpcwhitelist*` flags also dropped) |


### Run 4 (post NG-17/9/8 fixes)

Fourth measured run: **2026-10-30**, same branch, after three node-side fixes
landed in the working tree (uncommitted at run time):

- **NG-17** (named-object params): `setnetworkactive` binds `state`, `addnode`
  binds `node`/`command`/`v2transport`, `submitheader` binds `hexdata` - the
  three methods the 46 candidates reach with named-object params and that were
  still unbound (AST mining of the v31.1 framework's kwargs call sites;
  evidence in `results/run4/gap-probes.md`). Core v31.1 `RPCHelpMan` names,
  cited per method in the gap probes.
- **NG-9** (uacomment): new repeatable node option `-uacomment`/conf
  `uacomment` composing the version-handshake user agent and the
  `getnetworkinfo`/`getpeerinfo` subversion in Core's `FormatSubVersion`
  shape (`/bitcoin-rs:0.14.0(c1; c2)/`), validated at startup against Core's
  BIP-0014 safe-character subset and 256-byte cap with Core's exact error
  messages (the binary's startup-error stderr now uses Core's `Error: `
  console prefix, which the framework's FULL_REGEX match requires); the
  wrapper translates `-uacomment=X`/conf `uacomment=` instead of dropping it.
- **NG-8** (console logging): run 4 measured a fully-silent node log level
  `off` (bare global directive, no per-crate floors); in the landed tree the
  node keeps Core's bare-`off` semantics reverted and the wrapper's
  `printtoconsole=0` translation composes
  `--log-level=off,fjall=off,rocksdb=off` (`790010444`).

- bitcoin-rs commit: `a32b3856e` (run 4 measured the byte-identical
  working tree one commit later than `1f51eb4ab` plus these fixes; the
  built binary is the identity below)
- build: same profile as runs 1-3
  (binary sha256 `6bc8982feef1ad10193618a8b8f43415709302901b27ff0bf3cc47423fd60339`).
  A first execution on an intermediate binary (sha256 `84f97eb7...`, archived
  as `results/run4-attempt1/`) measured the same failure points everywhere
  except `feature_uacomment`, which caught a subversion composition bug
  (`/(c1; c2)` with a stray slash and no trailing slash); the fix is included
  in the published run's binary.
- runner: `tools/core-functional/run.sh --jobs 6 --timeout 300 --results-dir target/core-functional/results/run4`
  (137.3s wall); chain cache **reused** - run 3's `results/run3/cache` was
  seeded into `results/run4/cache` beforehand (same 199-block chain), and no
  test rebuilt it
- shim patches: the same three as runs 2-3, unchanged; the wrapper changed
  (uacomment translation, printtoconsole=0 -> off) and its smoke test with it
- closed-gap probes (direct, single fresh nodes): `results/run4/gap-probes.md`

**8 of the 46 selected candidates passed** (8 pass / 5 skip / 33 fail) - the
first status movements of the lane: four FAILs became PASSes
(`feature_uacomment`, `p2p_block_sync`, `p2p_invalid_locator`, `p2p_net_deadlock`).
Five tests moved to deeper failure points; two genuinely new gaps numbered
(NG-19 block-filter coverage of p2p-synced blocks, NG-20 split/rejoin block
sync). One run-3 race did not fire: NG-18's stale-parent abort was not
triggered this execution and `feature_versionbits_warning` progressed to the
underlying warning-content gap instead.

| test | status | cause | delta vs run 3 | one-line cause |
|------|--------|-------|----------------|----------------|
| feature_discover | PASS | | = | |
| mining_mainnet | PASS | | = | |
| rpc_decodescript | PASS | | = | |
| rpc_deprecated | PASS | | = | |
| feature_uacomment | PASS | | moved | NG-9 uacomment half closed: composition `(testnode0; foo)`, 256-byte cap, and unsafe-character startup errors all match Core |
| p2p_block_sync | PASS | | moved | NG-8 closed: fully silent console; body and exact-stderr teardown pass |
| p2p_invalid_locator | PASS | | moved | NG-8 closed: protocol legs already passed; teardown stderr now empty |
| p2p_net_deadlock | PASS | | moved | NG-8 closed: body already passed; teardown stderr now empty |
| example_test | SKIP | framework | = | wallet not compiled (ENABLE_WALLET=false) |
| feature_bind_port_discover | SKIP | framework | = | needs routable 1.1.1.1/2.2.2.2 on host interfaces |
| feature_bind_port_externalip | SKIP | framework | = | needs routable 1.1.1.1 on a host interface |
| interface_usdt_net | SKIP | framework | = | USDT tracepoints disabled in config.ini |
| interface_usdt_validation | SKIP | framework | = | USDT tracepoints disabled in config.ini |
| feature_bind_extra | FAIL | NG-12 | = | `-bind=IP:PORT=onion` dropped; node listens on conf port instead (`{0.0.0.0:11813}` vs expected `{127.0.0.1:11816}`) |
| feature_blocksdir | FAIL | NG-7 | = | `blocks_path` `<datadir>/regtest/blocks` never created; `-blocksdir` dropped |
| feature_chain_tiebreaks | FAIL | NG-6 | = | test reads `<datadir>/regtest/debug.log`: no debug log file at Core's path |
| feature_dirsymlinks | FAIL | NG-7 | = | manipulates `<datadir>/regtest/blocks` as a symlink: no Core-format blocks dir |
| feature_framework_startup_failures | FAIL | NG-14 | = | node starts successfully on conf/flags Core refuses at startup ("Should have failed earlier during startup") |
| feature_help | FAIL | NG-14 | = | `-fakearg` leg: Core exits 1, wrapper drops the flag, node runs -> `wait(60)` expires |
| feature_includeconf | FAIL | NG-9 | = | `-includeconf` dropped; subversion ends `(testnode0; main)` instead of `(testnode0; main; relative)` (the uacomment half now composes; the includeconf residual remains) |
| feature_loadblock | FAIL | NG-7 | moved | `setnetworkactive(state=False)` now binds (NG-17 closed) and `connect_nodes` passes; fails at `not(0 == 100)`: node1's `-loadblock=bootstrap.dat` is dropped |
| feature_posix_fs_permissions | FAIL | NG-6 | = | datadir+wallets perm checks pass; fails on missing `<datadir>/regtest/debug.log` |
| feature_presegwit_node_upgrade | FAIL | NG-13 | = | `softfork_active(node,"segwit")` true where the test expects false (deployment reporting) |
| feature_proxy | FAIL | NG-12 | = | proxied peer never appears in `getpeerinfo` (fails before the pong wait) |
| feature_reindex_init | FAIL | NG-7 | = | test corrupts Core-format `regtest/blocks/index` (absent); `-test=reindex_*` flag dropped |
| feature_remove_pruned_files_on_startup | FAIL | NG-7 | = | expects Core-format `regtest/blocks/blk00000.dat` pruning layout |
| feature_shutdown | FAIL | NG-4 | = | `stop(wait=1000)`: node refuses any stop argument (registry-documented deviation) with `-32602` |
| feature_startupnotify | FAIL | NG-12 | = | `-startupnotify` dropped; notify file never created (single-node test, no `connect_nodes` involved) |
| feature_versionbits_warning | FAIL | NG-12 | moved | NG-18's stale-parent race did not fire this execution; the generate calls pass and it fails at the warning content: `WARN_UNKNOWN_RULES_ACTIVE` absent from `getmininginfo.warnings` |
| interface_http | FAIL | NG-11 | = | RPC HTTP server closes the connection after the reply (no keep-alive); `conn.sock is not None` fails |
| interface_rpc | FAIL | NG-6 | = | `getrpcinfo.logpath` = `<data-dir>/debug.log` (file never written) vs Core's `<datadir>/<chain>/debug.log` |
| p2p_add_connections | FAIL | NG-12 | = | `add_outbound_p2p_connection` `wait_for_connect` times out (node never dials the configured outbound slot) |
| p2p_compactblocks_blocksonly | FAIL | NG-12 | = | node sends 2 `sendcmpct` where 1 expected (compact-blocks announce count) |
| p2p_compactblocks_hb | FAIL | NG-12 | moved | `disconnect_nodes` now matches peers (NG-9 closed) and the stale-inbound wait passes; fails at BIP152 high-bandwidth selection: relaying through one inbound promotes all three inbounds (`[False, True, True, True]` vs `[False, True, False, False]`) |
| p2p_getdata | FAIL | NG-12 | = | p2p `wait_until` (`blocks[best_block] == 1`) after getdata handshake probes |
| p2p_message_capture | FAIL | NG-12 | = | `-capture` message capture unsupported; no `msgs_recv.dat` written (IndexError on empty capture list) |
| p2p_nobloomfilter_messages | FAIL | NG-12 | = | p2p `wait_for_disconnect` after `msg_mempool` (bloom-filter negotiation expectations) |
| p2p_v2_encrypted | FAIL | NG-12 | = | v2-transport handshake wait (`add_outbound_p2p_connection(supports_v2_p2p=False)` leg) |
| rpc_bind | FAIL | NG-12 | = | rpc listen set lacks `::1` (IPv6) listener: `{127.0.0.1:18312}` vs `{127.0.0.1:18312, [::1]:18312}` |
| rpc_deriveaddresses | FAIL | NG-10 | = | error text: `key with hardened derivation steps cannot be a DerivedDescriptorKey` vs Core `Cannot derive script without private keys` |
| rpc_estimatefee | FAIL | NG-10 | = | error text: `invalid params: conf_target is required` vs Core's `estimatesmartfee ...` message |
| rpc_getblockfilter | FAIL | NG-19 | moved | the split/disconnect/reorg and `sync_blocks` now pass (NG-9 closed); the first `getblockfilter` on active-chain blocks that arrived via p2p sync answers `-1 Filter not found` (filter index has no filters for synced blocks) |
| rpc_getchaintips | FAIL | NG-20 | moved | `split_network` works (NG-9 closed); `join_network`'s `sync_all` times out after 60s - divergent chains are not exchanged after rejoin (the same split/mine/reconnect/sync pattern passed inside rpc_getblockfilter in this run; trigger unisolated, single execution) |
| rpc_getdescriptorinfo | FAIL | NG-10 | = | error text: `invalid params: descriptor is required` vs expected substring `getdescriptorinfo` |
| rpc_validateaddress | FAIL | NG-10 | = | invalid-address result omits `error`/`error_locations` fields Core returns |
| rpc_whitelist | FAIL | NG-11 | = | unauthorized RPC answered HTTP 403 where Core answers 401 (`rpcwhitelist*` flags also dropped) |


### Run 5 (PR-stack anchor)

Fifth measured run: **2026-10-31**, on branch `core-functional-evidence` (the
four-PR stack's tip), anchoring the campaign regrouping described in the
[Landing map](#landing-map) above.

- bitcoin-rs identity: `core-functional-evidence` tip - the tree's node-side
  content (`bin/`, `crates/`, `e2e/`, `docs/`) equals the campaign tip
  `7aff3c5d4`'s; only `tools/` placement and this record differ, and `tools/`
  is outside the binary build
- build: `cargo build --locked -p bitcoin-rs --profile quickstart --no-default-features --features fjall`
  (binary sha256 `6bc8982feef1ad10193618a8b8f43415709302901b27ff0bf3cc47423fd60339`,
  **byte-identical to run 4's binary** - binary identity survives the
  regrouping)
- Core suite: v31.1 extraction reused (`9be056a8a72b624dae9623b2f7bded92c2a21c91`)
- runner: `tools/core-functional/run.sh --jobs 6 --timeout 300 --results-dir target/core-functional/results/run5`
  (137.9s wall); chain cache **reused** - run 4's `results/run4/cache` was
  seeded into `results/run5/cache` beforehand (same 199-block chain), and no
  test rebuilt it
- shim patches: the same three as runs 2-4, unchanged

**8 of the 46 selected candidates passed** (8 pass / 5 skip / 33 fail) -
per-test statuses identical to run 4 for all 46 candidates; the only
failure-point difference is `rpc_validateaddress`, which hit a host RPC-port
collision at startup during the parallel run (`Address already in use`, an
execution-environment collision under `--jobs 6`, not a node change) and
whose isolated same-binary rerun reproduces run 4's exact NG-10 assertion
(`assert_equal(res["error"], error_str)`; `results/run5-recheck-rpcvalidateaddress/`).
One execution per candidate, same limits as runs 1-4. Run 5's own statuses
live in its report (`target/core-functional/results/run5/report.json`); a
per-test table is not duplicated for this pre-rebase twin - run 5b below
re-anchors the same 46 statuses on the landed stack and carries the table.

### Run 5b (post-rebase re-anchor)

Sixth measured run: **2026-10-31**, on branch `core-functional-evidence`
after the four-PR stack was rebased onto `origin/main` (`cd12d7c90`). The
rebase pulled in main's node-side changes since the campaign base
`3d97f4929` (p2p sync/broadcast/ingress stabilization, chainstate sigop and
replay fixes, mempool/rpc fixes, test-suite consolidation), so run 5's
"binary identical to run 4" anchor no longer held and the suite was re-run.

- bitcoin-rs identity: rebased `core-functional-evidence` tip
- build: `cargo build --locked -p bitcoin-rs --profile quickstart --no-default-features --features fjall`
  (binary sha256 `50131c6a6b03e36728a5dbde949ed7cf207b98bf5c5a0fb0673754d13d362f46`,
  **not** byte-identical to runs 4-5 - main's node-code changes are in)
- Core suite: v31.1 extraction reused (`9be056a8a72b624dae9623b2f7bded92c2a21c91`)
- runner: `tools/core-functional/run.sh --jobs 6 --timeout 300 --results-dir target/core-functional/results/run5b`
  (137.0s wall); chain cache **reused** - run 5's `results/run5/cache` was
  seeded into `results/run5b/cache` beforehand, the runner's new serial
  cache-prime pass (create_cache.py, this stack's review fix) confirmed it
  present in 0.2s, and no test rebuilt it
- shim patches: the same three as runs 2-5, unchanged

Coverage note: run 5b measured the rebased stack tip as of 2026-10-31. Node
code landed on PRs 2 and 3 after that measurement is unmeasured by this
record: PR 2's `33d9449bf`, `9bbf93dcf`, and `d5eb93b45` (MessageAccount
table, v2 undefined-type charging, per-frame burst accounting, outbound
control lane) and PR 3's `790010444` and `9db0b4f4e` (stop reply string,
one-line `--version`, `run.rs` `off` revert, the
`syncwithvalidationinterfacequeue` barrier). The gap is stated rather than
covered: a future run re-anchoring on this tip owns the fresh binary
identity and report.

**8 of the 46 selected candidates passed** (8 pass / 5 skip / 33 fail) -
per-test statuses identical to runs 4 and 5 for all 46 candidates, and every
failure reproduces run 4's exact failure point (verified by comparing the
per-test `log_tail` records; the only differences are ephemeral ports,
timestamps, results-dir paths, and chain hashes). `rpc_validateaddress`
reached run 4's exact NG-10 assertion directly (`check_invalid` ->
`KeyError: 'error'`) - run 5's host RPC-port collision did not recur, and no
runner-level timeout fired (the ~60s failures are the framework's own
internal waits, as in runs 3-5). One execution per candidate, same limits as
runs 1-5.

Per-test statuses below are read from run 5b's measured report
(`target/core-functional/results/run5b/report.json`); causes reuse run 4's
triage (the summary above verified every failure reproduces run 4's exact
failure point), with run 5b's own ephemeral ports where a cause cites them.

| test | status | cause | delta vs run 4 | one-line cause |
|------|--------|-------|----------------|----------------|
| feature_discover | PASS | | = | |
| mining_mainnet | PASS | | = | |
| rpc_decodescript | PASS | | = | |
| rpc_deprecated | PASS | | = | |
| feature_uacomment | PASS | | = | NG-9 uacomment half closed: composition `(testnode0; foo)`, 256-byte cap, and unsafe-character startup errors all match Core |
| p2p_block_sync | PASS | | = | NG-8 closed: fully silent console; body and exact-stderr teardown pass |
| p2p_invalid_locator | PASS | | = | NG-8 closed: protocol legs already passed; teardown stderr now empty |
| p2p_net_deadlock | PASS | | = | NG-8 closed: body already passed; teardown stderr now empty |
| example_test | SKIP | framework | = | wallet not compiled (ENABLE_WALLET=false) |
| feature_bind_port_discover | SKIP | framework | = | needs routable 1.1.1.1/2.2.2.2 on host interfaces |
| feature_bind_port_externalip | SKIP | framework | = | needs routable 1.1.1.1 on a host interface |
| interface_usdt_net | SKIP | framework | = | USDT tracepoints disabled in config.ini |
| interface_usdt_validation | SKIP | framework | = | USDT tracepoints disabled in config.ini |
| feature_bind_extra | FAIL | NG-12 | = | `-bind=IP:PORT=onion` dropped; node listens on conf port instead (`{0.0.0.0:12083}` vs expected `{127.0.0.1:12086}`) |
| feature_blocksdir | FAIL | NG-7 | = | `blocks_path` `<datadir>/regtest/blocks` never created; `-blocksdir` dropped |
| feature_chain_tiebreaks | FAIL | NG-6 | = | test reads `<datadir>/regtest/debug.log`: no debug log file at Core's path |
| feature_dirsymlinks | FAIL | NG-7 | = | manipulates `<datadir>/regtest/blocks` as a symlink: no Core-format blocks dir |
| feature_framework_startup_failures | FAIL | NG-14 | = | node starts successfully on conf/flags Core refuses at startup ("Should have failed earlier during startup") |
| feature_help | FAIL | NG-14 | = | `-fakearg` leg: Core exits 1, wrapper drops the flag, node runs -> `wait(60)` expires |
| feature_includeconf | FAIL | NG-9 | = | `-includeconf` dropped; subversion ends `(testnode0; main)` instead of `(testnode0; main; relative)` (the uacomment half now composes; the includeconf residual remains) |
| feature_loadblock | FAIL | NG-7 | = | `setnetworkactive(state=False)` now binds (NG-17 closed) and `connect_nodes` passes; fails at `not(0 == 100)`: node1's `-loadblock=bootstrap.dat` is dropped |
| feature_posix_fs_permissions | FAIL | NG-6 | = | datadir+wallets perm checks pass; fails on missing `<datadir>/regtest/debug.log` |
| feature_presegwit_node_upgrade | FAIL | NG-13 | = | `softfork_active(node,"segwit")` true where the test expects false (deployment reporting) |
| feature_proxy | FAIL | NG-12 | = | proxied peer never appears in `getpeerinfo` (fails before the pong wait) |
| feature_reindex_init | FAIL | NG-7 | = | test corrupts Core-format `regtest/blocks/index` (absent); `-test=reindex_*` flag dropped |
| feature_remove_pruned_files_on_startup | FAIL | NG-7 | = | expects Core-format `regtest/blocks/blk00000.dat` pruning layout |
| feature_shutdown | FAIL | NG-4 | = | `stop(wait=1000)`: node refuses any stop argument (registry-documented deviation) with `-32602` |
| feature_startupnotify | FAIL | NG-12 | = | `-startupnotify` dropped; notify file never created (single-node test, no `connect_nodes` involved) |
| feature_versionbits_warning | FAIL | NG-12 | = | NG-18's stale-parent race did not fire this execution; the generate calls pass and it fails at the warning content: `WARN_UNKNOWN_RULES_ACTIVE` absent from `getmininginfo.warnings` |
| interface_http | FAIL | NG-11 | = | RPC HTTP server closes the connection after the reply (no keep-alive); `conn.sock is not None` fails |
| interface_rpc | FAIL | NG-6 | = | `getrpcinfo.logpath` = `<data-dir>/debug.log` (file never written) vs Core's `<datadir>/<chain>/debug.log` |
| p2p_add_connections | FAIL | NG-12 | = | `add_outbound_p2p_connection` `wait_for_connect` times out (node never dials the configured outbound slot) |
| p2p_compactblocks_blocksonly | FAIL | NG-12 | = | node sends 2 `sendcmpct` where 1 expected (compact-blocks announce count) |
| p2p_compactblocks_hb | FAIL | NG-12 | = | `disconnect_nodes` now matches peers (NG-9 closed) and the stale-inbound wait passes; fails at BIP152 high-bandwidth selection: relaying through one inbound promotes all three inbounds (`[False, True, True, True]` vs `[False, True, False, False]`) |
| p2p_getdata | FAIL | NG-12 | = | p2p `wait_until` (`blocks[best_block] == 1`) after getdata handshake probes |
| p2p_message_capture | FAIL | NG-12 | = | `-capture` message capture unsupported; no `msgs_recv.dat` written (IndexError on empty capture list) |
| p2p_nobloomfilter_messages | FAIL | NG-12 | = | p2p `wait_for_disconnect` after `msg_mempool` (bloom-filter negotiation expectations) |
| p2p_v2_encrypted | FAIL | NG-12 | = | v2-transport handshake wait (`add_outbound_p2p_connection(supports_v2_p2p=False)` leg) |
| rpc_bind | FAIL | NG-12 | = | rpc listen set lacks `::1` (IPv6) listener: `{127.0.0.1:18534}` vs `{127.0.0.1:18534, [::1]:18534}` |
| rpc_deriveaddresses | FAIL | NG-10 | = | error text: `key with hardened derivation steps cannot be a DerivedDescriptorKey` vs Core `Cannot derive script without private keys` |
| rpc_estimatefee | FAIL | NG-10 | = | error text: `invalid params: conf_target is required` vs Core's `estimatesmartfee ...` message |
| rpc_getblockfilter | FAIL | NG-19 | = | the split/disconnect/reorg and `sync_blocks` now pass (NG-9 closed); the first `getblockfilter` on active-chain blocks that arrived via p2p sync answers `-1 Filter not found` (filter index has no filters for synced blocks) |
| rpc_getchaintips | FAIL | NG-20 | = | `split_network` works (NG-9 closed); `join_network`'s `sync_all` times out after 60s - divergent chains are not exchanged after rejoin (the same split/mine/reconnect/sync pattern passed inside rpc_getblockfilter in this run; trigger unisolated, single execution) |
| rpc_getdescriptorinfo | FAIL | NG-10 | = | error text: `invalid params: descriptor is required` vs expected substring `getdescriptorinfo` |
| rpc_validateaddress | FAIL | NG-10 | = | invalid-address result omits `error`/`error_locations` fields Core returns (run 4's exact assertion reached directly, `check_invalid` -> `KeyError: 'error'`; run 5's host port collision did not recur) |
| rpc_whitelist | FAIL | NG-11 | = | unauthorized RPC answered HTTP 403 where Core answers 401 (`rpcwhitelist*` flags also dropped) |


### Node gaps for the next phase

Order below preserves introduction order - the run-1 triage order first,
then NG-16..NG-20 appended as later runs isolated them - with one deliberate
deviation from that rule: **NG-4 sits last** because it is a keep-or-lift
decision on a documented deviation, not a fix-pending gap (it blocks 1 test,
`feature_shutdown`, the same tier as NG-19/NG-20). The ledger is not sorted
by the latest blast radius because those counts moved between runs; each
entry states its own measured tests-blocked count as of the latest run
(run 5b, which reproduced run 4's statuses and failure points on the rebased
tree). Evidence: the per-test `tmp/<test>/test_framework.log` and per-datadir
`wrapper-dropped-flags.log` under `target/core-functional/results/run4/`;
runs 1-3's equivalents under `results/final/`, `results/run2/`, and
`results/run3/`; direct probe evidence in `results/run2/gap-probes.md`,
`results/run3/gap-probes.md`, and `results/run4/gap-probes.md`;
raw unshimmed reproductions under `results/raw-evidence*/`.

- ~~**NG-1 JSON-RPC params-as-object**~~ **CLOSED by `862068637`** (run 2
  verified): `"params": {}` is accepted server-wide for zero-arg methods
  (`getbestblockhash` with `params:{}` returns the hash) and
  `generatetoaddress(nblocks=, address=)` binds its named-object form (probe
  mined a block). The shim's params-rewrite patch stays deleted.
- ~~**NG-5 `getpeerinfo` pong accounting**~~ **accounting half CLOSED by
  `cb9cf472c`** (run 2 verified: handshake frames appear in
  `bytesrecv_per_msg`/`bytessent_per_msg` with real wire sizes); the actual
  blocker of the six multi-node tests was newly isolated by run 2 as
  **NG-16** (no originated ping), which subsumes this entry's remaining scope.
  Run-1 text for the record: the framework's `connect_nodes` waits for
  `bytesrecv_per_msg['pong'] >= 29` after `addnode onetry`; never observed, so
  every multi-node test timed out in setup (6 measured tests).
- ~~**NG-2 `syncwithvalidationinterfacequeue` missing**~~ **CLOSED by
  `862068637`** (run 2 verified: answers `null` to `params:{}`; the shim's
  no-op for it stays deleted).
- **NG-3 `setmocktime` missing** (OPEN): cache build and `set_node_times`;
  run 2 probe: `setmocktime(-1)` still answers
  `{"code":-32601,"message":"method not found: setmocktime"}` where Core
  answers its `-8` range error. No candidate test calls it itself; still
  no-op'd by shim patch 2 (the run-2 cache was reused, so the cache-build
  path did not exercise it either).
- **NG-6 no debug log at Core's path**: nothing writes
  `<datadir>/<chain>/debug.log`; `getrpcinfo.logpath` reports
  `<data-dir>/debug.log` and that file is never written either (3 tests;
  unchanged by run 4 - `off` silences the console but no log file appears).
- **NG-7 no Core-format blocks dir layout**: blocks live in the node's own
  storage (`bitcoin-rs-data/blocks`), so `regtest/blocks`,
  `blk00000.dat`, `blocks/index`, `-blocksdir`, `-loadblock`, `-reindex`
  have no counterpart (5 tests; run 4 moved `feature_loadblock` here from
  NG-17 - it now passes `setnetworkactive`/`connect_nodes` and fails on the
  dropped `-loadblock=bootstrap.dat` with `not(0 == 100)`).
- ~~**NG-8 console logging**~~ **CLOSED (run 4 verified; landed tree keeps
  the closure via the wrapper directive)**: run 4 measured a fully-silent
  node log level `off` (bare global `EnvFilter` directive) plus the
  wrapper's `printtoconsole=0` translation changed from `--log-level=warn`
  to `--log-level=off`. In the landed tree the node-side bare `off` was
  reverted to Core's semantics (`off` means `off,fjall=warn,rocksdb=warn`
  again) and the closure moved entirely into the wrapper, which now
  composes `--log-level=off,fjall=off,rocksdb=off` (`790010444`) - the same
  fully-silent console the tests assert. Direct probe
  (`results/run4/gap-probes.md`): a node at `off` writes 0 stderr bytes
  across a dial the node warns about, where `warn` writes 489. Run 4
  verified all three blocked tests PASS
  (`p2p_invalid_locator`, `p2p_block_sync`, `p2p_net_deadlock`). Run-3 text
  for the record: Core's `printtoconsole=0` console is silent while bitcoin-rs
  wrote WARN lines to stderr, breaking exact-stderr teardown assertions.
  Console silence only - NG-6 (no debug.log at Core's path) is untouched.
- ~~**NG-9 subversion/uacomment - uacomment half CLOSED (uacomment-phase
  working tree, run 4 verified); `-includeconf` residual OPEN (1 test)**~~:
  the node gained a repeatable `-uacomment` CLI flag and conf key composing
  the handshake user agent and the `getnetworkinfo`/`getpeerinfo` subversion
  in Core's `FormatSubVersion` shape (`/bitcoin-rs:0.14.0(c1; c2)/`;
  `crates/primitives` `sub_version`), validated at startup against Core's
  BIP-0014 safe subset and 256-byte cap with Core's exact error messages
  (the binary's startup-error stderr now uses Core's `Error: ` prefix);
  the wrapper translates `-uacomment=X`/conf `uacomment=` instead of
  dropping them. Run 4 verified: `feature_uacomment` PASSES, and
  `disconnect_nodes`/`split_network` peer matching works, which unblocked
  `p2p_compactblocks_hb`, `rpc_getchaintips`, and `rpc_getblockfilter`
  into their bodies (now NG-12/NG-20/NG-19 respectively). The residual is
  `-includeconf`: the wrapper still drops it (no node-side conf-include
  mechanism), so `feature_includeconf` fails at
  `subversion.endswith("main; relative)")` - the framework's includeconf
  files never contribute their `uacomment=relative` entries.
- **NG-10 RPC error/result-shape deviations**: `validateaddress` invalid
  results lack `error`/`error_locations`; `deriveaddresses`/`estimatefee`/
  `getdescriptorinfo` error texts differ from Core's (4 tests).
- **NG-11 HTTP layer**: no keep-alive on the RPC port (`interface_http`);
  unauthorized requests get 403 where Core's RPC server answers 401
  (`rpc_whitelist`).
- **NG-12 p2p surface**: onion-qualified binds, proxied-peer visibility in
  `getpeerinfo`, `-startupnotify`, p2p message capture, v2-transport
  handshake expectations, compact-blocks negotiation (`sendcmpct` announce
  counts; high-bandwidth peer selection - run 4 measured the selection shape
  for the first time: relaying through one inbound promotes all three
  inbounds in `p2p_compactblocks_hb`), bloom-filter negotiation, IPv6 rpc
  binds, node-dialed outbound slots, getdata handshake-probe waits, and the
  versionbits warning content (`WARN_UNKNOWN_RULES_ACTIVE` absent from
  `getmininginfo.warnings`; run 4 moved `feature_versionbits_warning` here
  once the NG-18 race stopped firing) - 12 tests (run 4 added
  `p2p_compactblocks_hb` from NG-9 and `feature_versionbits_warning` from
  NG-18; run 3 counted 10).
- **NG-13 deployment reporting**: `getdeploymentinfo`-backed
  `softfork_active(node,"segwit")` returns active where
  `feature_presegwit_node_upgrade` expects inactive.
- **NG-14 startup strictness** (scope sharpened by run 2): unknown/invalid
  conf keys are ignored by the node's conf parser where Core fails fast
  (`feature_framework_startup_failures`), and unknown **CLI flags** - the
  newly exposed argv half that moved `feature_help` here - are dropped by the
  wrapper and the node then starts, where Core exits 1 with
  "Error parsing command line arguments". Invoked directly the node does fail
  on unknown flags, but with clap's exit code 2 and message, not Core's 1.
- ~~**NG-15 no `--version` flag**~~ **CLOSED by `862068637`** (run 2 verified
  the flag exists and `feature_help` passes that leg; run 2 measured the
  earlier copyright-bearing form). The landed `--version` prints exactly one
  line, `bitcoin-rs daemon version <ver>` - no copyright block
  (`790010444`).
- ~~**NG-16 no originated ping/keepalive**~~ **CLOSED by commit `e18b2ade2`**
  (run 3 measured the byte-identical pre-commit tree; binary sha256
  `800aa9739c...`, see Run 3): the p2p `Keepalive` owner now owes the first
  probe on the first message-loop pass after the handshake completes - Core
  31.1 `MaybeSendPing` semantics with `m_ping_start` epoch-initialized - on
  both inbound and outbound sessions, then keeps the existing 2-minute
  idle-gated cadence with a fresh nonce per probe; the 20-minute
  send/receive-silence expiry was already the owner's (Core `InactivityCheck`
  shape). Deviations kept and recorded in `docs/contracts/p2p-wire.md`
  (ping/pong row): no unconditional 2-minute cadence on busy links, no
  pong-nonce matching (so Core's pong-specific 20-minute timeout stays
  unenforced). Run 3 verified all six blocked tests moved past
  `connect_nodes`; direct probe in `results/run3/gap-probes.md`.
- ~~**NG-17 named-object params rejected for non-zero-arg RPCs**~~ **CLOSED
  (uacomment-phase working tree, run 4 verified)**: the three candidate-reached
  methods gained Core's `RPCHelpMan` argument names in
  `bind_named_params` - `setnetworkactive` (`state`), `addnode`
  (`node`/`command`/`v2transport`), `submitheader` (`hexdata`) - selected by
  AST-mining the v31.1 framework's kwargs call sites (the only still-unbound
  named-object forms the 46 candidates reach; `getrawmempool`/
  `getrawtransaction`/`getorphantxs` named sites exist in wallet.py/
  mempool_util.py but no candidate reaches them; `stop(wait=...)` stays
  refused as NG-4's documented deviation). Run 4 verified `feature_loadblock`
  passed `setnetworkactive(state=False)` and moved to its `-loadblock` leg;
  direct probes in `results/run4/gap-probes.md`.
- **NG-18 `generatetoaddress` hard-fails on submit-time stale parent** (OPEN,
  race-dependent; 0 tests blocked in run 4): when the best tip advances
  between template and submission, `ApplyError::PrevHashMismatch` surfaces as
  `-32603 internal error: generated block was not accepted:
  Rejected("inconclusive-not-best-prevblk")` and aborts the whole call
  (`crates/mining` `STALE_PARENT_REASON`); Core's generate builds each block
  on the then-current tip and does not error the call. Measured in run 3's
  `feature_versionbits_warning` (line 73, immediately after
  `send_blocks_with_version`'s unsynced burst - a race; run 2's body passed
  the same calls, single execution per candidate, no flakiness claim) and as
  the error mechanism inside run 3's `rpc_getblockfilter` overlapping
  generates (primary attribution NG-9). Run 4 did not trigger the race:
  `feature_versionbits_warning`'s generate calls passed and the test failed
  at the NG-12 warning-content leg instead; the mechanism is unchanged and
  stays open on run 3's evidence. Probe: `results/run3/gap-probes.md`.
- **NG-19 block filter index has no filters for p2p-synced blocks** (NEW,
  run 4; 1 test): with `-blockfilterindex=1`, `getblockfilter` answers
  `-1 Filter not found. This could be because the block was not connected to
  the active chain.` for blocks that arrived through p2p sync - measured in
  `rpc_getblockfilter` after the NG-9 closure let its split/reorg/sync setup
  pass (`sync_blocks` succeeded, then the first `getblockfilter` on the
  synced active-chain blocks failed). Filters for locally generated blocks
  were not contradicted by this run (the test died on the first synced-block
  query).
- **NG-20 block sync does not complete after split/rejoin** (NEW, run 4;
  1 test): `rpc_getchaintips`'s `join_network` + `sync_all` times out after
  60s when both halves hold divergent chains built on a common ancestor
  (10 vs 20 blocks) - the divergent chains are not exchanged across the
  rejoined links. Honest caveat: the same split/mine/reconnect/`sync_blocks`
  pattern passed inside `rpc_getblockfilter` in this same run (3 vs 4 blocks,
  manual `disconnect_nodes`/`connect_nodes` pairs rather than
  `split_network`), so the trigger is unisolated and could be topology-,
  size-, or timing-dependent; single execution, no flakiness claim.
- **NG-4 (deliberate, documented) `stop` wait argument**: the registry
  documents that any stop argument is refused; `feature_shutdown` measures
  exactly that (`stop(wait=1000)` -> `-32602`, byte-identical across runs 1-4).
  If kept, that test can never pass; if lifted, delete the shim's
  wait=0 strip.

### Honest limits of this measurement

- 46 of Core's 262 functional scripts were selected by static RPC-dependency
  analysis; the other 216 were not run and nothing here speaks for them.
- Run 1 carried four shim patches that adapted framework plumbing around
  NG-1/2/3/4 so the batch could measure anything at all; runs 2-4 carried the
  three that remain (setmocktime no-op, stop wait=0 strip, MiniWallet
  `generatetoaddress` retarget), unchanged. With all patches disabled, run 1's
  raw reproductions (`results/raw-evidence*/`) show every candidate dying at
  the framework's first probe; the run-2-relevant deletions (params rewrite,
  sync no-op) were verified against the closed gaps by direct probes
  (`results/run2/gap-probes.md`). Passes and failures above are therefore
  "node + disclosed plumbing shim", not bare-node behavior.
- The wrapper drops Core flags bitcoin-rs has no equivalent for; each drop is
  logged per datadir. Failures that hinge on a dropped flag are attributed to
  the node gap it represents, not hidden. (`-uacomment=` was translated
  rather than dropped from run 4 on.)
- Every run is a single execution per candidate on one machine; nothing here
  is a flakiness or performance claim (run 3's NG-18 is a measured
  race-triggered failure whose run-2 and run-4 counterparts passed the same
  calls; NG-20's trigger is likewise unisolated). Run 4 was executed twice -
  the first binary composed the subversion with a stray slash
  (`results/run4-attempt1/`, identical failure points everywhere except
  `feature_uacomment`, which caught it) - and the published run is the second
  execution on the corrected binary.

## Usage

```sh
# 1. Extract the pinned Core suite (idempotent; wipes and re-extracts)
tools/core-functional/fetch-core-tests.sh --core-repo ~/git/bitcoin   # or: export BITCOIN_CORE_REPO=~/git/bitcoin

# 2. Point at a built node binary
cargo build --release --bin bitcoin-rs               # owned by other phases
export BITCOIN_RS_BIN=$PWD/target/release/bitcoin-rs

# 3. Run
tools/core-functional/run.sh                         # all clean candidates
tools/core-functional/run.sh rpc_getchaintips feature_help
tools/core-functional/run.sh --jobs 8 --timeout 600 --results-dir target/core-functional/results/quick
tools/core-functional/run.sh --list                  # list candidate tests
```

Results land in `target/core-functional/results/<timestamp>/`:
`report.md` (human table), `report.json` (machine record incl. Core tag +
commit, node binary path, per-test exit codes and failure log tails), plus
per-test `tmp/` datadirs retained for debugging.

## Pieces

| path | role |
|------|------|
| `fetch-core-tests.sh` | `git archive`s `test/functional`, `contrib/linearize`, `share/rpcauth` from a verified tag in a local Core checkout, writes a `PROVENANCE` stamp, symlinks `<dest>/bin/bitcoind` -> `bin/bitcoind-wrapper`. Refuses to run if the tag does not resolve. |
| `bin/bitcoind-wrapper` | Python adapter exec'd by the framework. Translates Core-style argv to bitcoin-rs flags, derives a supported-only `bitcoin-rs-derived.conf` from the framework's `bitcoin.conf`, and creates the RPC cookie file where the framework reads it (`<datadir>/<chain>/.cookie`), pointing the node at it via `--rpc-cookie`. The node's own data directory is `<datadir>/bitcoin-rs-data` (bitcoin-rs refuses a fresh datadir holding foreign entries, and the framework always pre-populates `<datadir>/` with `bitcoin.conf` and `stderr/`/`stdout/`; keeping the node dir at the datadir top level means the framework's cache copytree carries the premined chain in the node's own storage format). Also creates the Core-facing layout `<datadir>/<chain>/{,wallets}` (mode 0700) that Core bitcoind always creates, the framework's cache teardown `rmdir`s, and `feature_posix_fs_permissions.py` asserts. With no chain marker anywhere the wrapper defaults to mainnet (Core's default), so the cookie lands at `<datadir>/.cookie` where the framework's `get_auth_cookie(datadir, "")` reads it. `printtoconsole=0` (the framework's setting) translates to the fully-silent composed directive `--log-level=off,fjall=off,rocksdb=off` (run 4 measured the earlier bare `--log-level=off`; the closest equivalent of Core's "console stays quiet" behavior that tests assert at teardown). Unmappable flags/conf keys are dropped and appended as JSON lines to `<datadir>/wrapper-dropped-flags.log`. Silent on stdout/stderr in success paths. Reads `BITCOIN_RS_BIN` (required) and `BITCOIN_RS_EXTRA_ARGS` (optional, appended verbatim). |
| `config.ini` | Template framework config; `run.sh` renders `@CORE_TESTS_DIR@` into the results dir. `ENABLE_BITCOIND=true`, every other component `false` so wallet/cli/zmq-dependent tests take the framework's own skip paths. |
| `shim/sitecustomize.py` | PYTHONPATH startup hook; every patch is an explicitly recorded bitcoin-rs deviation (see the file header); patches (2) and (3) carry a disable env var while patch (1) is unconditional. Three patches remain active: (1) monkeypatches `test_framework.wallet.MiniWallet.generate` to mine via the implemented `generatetoaddress` RPC instead of the unimplemented `generatetodescriptor` (ADDRESS_OP_TRUE mode only; other modes keep upstream behavior and fail loudly); (2) no-ops the one framework-plumbing RPC the node still lacks, `setmocktime` (no candidate test calls it itself; NG-3); (3) strips exactly the `stop(wait=0)` teardown form (Core's hidden wait argument; the node's stop takes none - non-zero waits still fail honestly; NG-4). Two run-1 patches were deleted once the node closed their gaps and run 2 + direct probes verified the closures: the client-side params-rewrite for `"params":{}` and `generatetoaddress` named-object forms (NG-1, closed by `862068637`) and the `syncwithvalidationinterfacequeue` no-op (NG-2, same commit). No Core code is copied; the patches preserve upstream post-conditions where they apply. |
| `run.sh` + `bin/runner.py` | Runner: per-test `python3 <test>.py --configfile <rendered config.ini> --tmpdir <results>/tmp/<test> --cachedir <results>/cache` with the shim on `PYTHONPATH`, cwd `= <dest>/test/functional`. Before the parallel pool starts, runs the extracted tree's `create_cache.py` once, serially, against the shared cachedir (Core's own `test_runner.py` pattern) so parallel jobs never race to build the cache; the framework skips mining when the cache node dir already exists, so pre-seeded caches are reused. Each test runs as its own process group; a timeout kills the whole group so node processes a timed-out test spawned cannot linger and hold ports. Classifies 0=PASS, 77=SKIP, else=FAIL (timeout tracked separately). Fails fast (exit 2, before running anything) when `BITCOIN_RS_BIN` is unset/missing. Records per-test exit code, duration, framework-log tail, and captured stdout/stderr tails in `report.json` (a relative `--results-dir` is resolved, since tests run with a different cwd). |
| `tests/clean-candidates.txt` | The 46 tests selected by static RPC-dependency analysis at derivation time: an upper bound on candidates, not pass claims. |
| `tests/wrapper_smoke.py` | Wrapper regression guard: covers the translation table, cookie/datadir layout (including the mainnet default and `bitcoin-rs-data` redirect), drop logging, and error paths. |
| `tests/triage_summary.py` | Scratch aid: one line per non-PASS test with the innermost exception from its `test_framework.log`. |

## Wrapper translation table

Verified against `crates/node/src/options.rs` and `bin/bitcoin-rs/src/config.rs`
(`parse_for_network`): unknown conf keys are ignored, known keys parse
strictly, `[<network>]` sections apply only when `--network` matches, and CLI
outranks conf. Repeated Core flags follow Core's last-occurrence-wins rule
(the framework itself passes `-v2transport=0` base plus a test's
`-v2transport=1`); since bitcoin-rs rejects repeated CLI flags and an option
present through both conf and argv ("cannot be used multiple times"), the
wrapper emits only the last occurrence and suppresses conf lines whose option
was already set as a CLI flag (suppressions appear in the drop log).
Mapped Core flag -> bitcoin-rs flag (both `-flag=v` and `-flag` forms):

| Core | bitcoin-rs |
|------|------------|
| `-datadir=X` | `--data-dir=X/bitcoin-rs-data` (framework writes `X/bitcoin.conf`; adapter derives `X/bitcoin-rs-derived.conf` via `--bitcoin-conf`; the node gets its own initially-empty data dir because it refuses a fresh datadir holding foreign entries - see the wrapper row above) |
| no chain marker anywhere | `--network=mainnet` (Core's default chain), chain subdir "" (cookie at `<datadir>/.cookie`) |
| `-regtest` / `-testnet` / `-testnet4` / `-signet` / `-chain=X` / `-main` | `--network=regtest / testnet3 / testnet4 / signet / mainnet / X` |
| `-bind=IP:PORT` | `--p2p-listen=IP:PORT` (bare `-bind=IP` gains the effective port from `port=`; binds with `=onion` qualifiers are dropped) |
| `port=P` (conf/argv, when no explicit bind) | `--p2p-listen=0.0.0.0:P` |
| `-nolisten` / `-listen=0` | `listen=0` line in the derived conf (the node maps it to an empty listen set) |
| `-connect=host:port` | `--connect=host:port` (`-connect=0` dropped) |
| `-v2transport=B` | `--v2transport=B` |
| `-uacomment=X` | `--uacomment=X` (repeatable; occurrences append and compose Core's `(c1; c2)` subversion group - NG-9) |
| `-dnsseed=B` | `--dns-seeds-enabled=B` |
| `rpcport=P` (conf/argv) | `--rpc-bind=127.0.0.1:P` (seeds the single rpc socket; an explicit `-rpcbind=` overrides it - see next row) |
| `-rpcbind=IP[:PORT]` | `--rpc-bind=...` (literal sockets only; bitcoin-rs takes a single rpc bind and rejects repeats, so the conf `rpcport=` default and every `-rpcbind=` collapse to one last-occurrence-wins `--rpc-bind` emission) |
| `-proxy` / `-onion` / `-i2psam` / `-torcontrol=IP:PORT` | `--proxy` / `--onion-proxy` / `--i2p-sam` / `--tor-control` |
| `-onlynet=list` | `--onlynet=list` (validated) |
| `-dbcache=N` / `-prune=N` | `--dbcache-mb=N` / `--prune-target-mb=N` |
| `-txindex=B` / `-blockfilterindex=B` / `-rest=B` / `-persistmempool=B` | same-meaning bitcoin-rs flags |
| `-printtoconsole=0` (conf/argv) | `--log-level=off,fjall=off,rocksdb=off` (Core keeps the console silent; the node's bare `off` keeps the `fjall=warn,rocksdb=warn` floors, so full silence composes the directive per target — tests assert an empty stderr at stop) |
| `-proxyrandomize=B` / `-i2pacceptincoming=B` | `--proxy-randomize-credentials=B` / `--i2p-accept=B` |
| `-h` / `-version` | `--help` / `--version` (`--version` prints the node's own one-line version notice and exits 0 - NG-15 fixed after the 2026-10-30 measured run, where the binary rejected the flag with clap exit 2) |

Conf keys carried into the derived conf (Core spelling, under the original
network sections): `dbcache, prune, txindex, blockfilterindex, rest, dnsseed,
v2transport, onlynet, proxy, onion, i2psam, torcontrol, proxyrandomize,
i2pacceptincoming, uacomment, listen`. `rpcuser`/`rpcpassword`/`rpccookiefile`
become the cookie file the adapter writes (see below), and
`printtoconsole=0` becomes the fully-silent composed directive
(`--log-level=off,fjall=off,rocksdb=off`; see the table). `-uacomment=X`
(argv) translates to a repeatable `--uacomment=X` flag and a conf `uacomment=`
line is carried verbatim (both accumulate; a conf line whose option was
already set on the CLI is suppressed, per the CLI-outranks-conf rule). Everything else - including the
framework's `server, keypool, discover, fixedseeds, listenonion, peertimeout,
shrinkdebugfile, natpmp, fallbackfee, rpcservertimeout, rpcdoccheck, rpcthreads,
maxconnections, par, unsafesqlitesync, connect=0` and
test flags like `-logtimemicros, -debug, -debugexclude, -wallet*,
-loadblock, -includeconf, -whitelist, -rpcauth, -startupnotify, -stopatheight` -
is dropped and logged to `<datadir>/wrapper-dropped-flags.log`, one JSON object
per drop with origin (`argv` / `conf[:section]`), token, and reason.

### RPC cookie resolution

The framework reads credentials from `<datadir>/<chain>/.cookie`
(`test_framework/util.py get_auth_cookie`) and prefers that file over conf
`rpcuser`/`rpcpassword`. bitcoin-rs's `--rpc-cookie` *reads* an existing
`user:password` file (its own generated cookie, written only when no auth is
configured, lands at `<data-dir>/.cookie` - one level shallower than the
framework's lookup, and not per-chain). The adapter therefore creates
`<datadir>/<chain>/.cookie` itself (`__cookie__:<64 hex>`, or
`<user>:<password>` when rpcuser+rpcpassword are configured) before exec and
points the node at it with `--rpc-cookie=<path>`: both sides then authenticate
against the same file with no node-side changes.

## Provenance and license

`fetch-core-tests.sh` extracts only from a git tag resolvable in a local Core
checkout and stamps `PROVENANCE` (tag, commit, UTC date, source repo, paths)
into the extraction directory; the runner copies tag/commit into every report.
Bitcoin Core is MIT-licensed; the extracted tree keeps its copyright headers
intact and lives only in the gitignored `target/` scratch area - it is never
committed to this repository. `shim/sitecustomize.py` patches the framework at
runtime from outside and contains no Core code.

## How this maps to the repo's evidence rules

Per `AGENTS.md`, compatibility claims need measured evidence owned by a
durable artifact. This lane's runner report (`report.json`/`report.md`,
including Core tag + commit, node binary path, per-test exit codes, durations,
and failure log tails) is the single evidence owner for any future
"bitcoin-rs passes Core functional test X" statement; the candidate list is
explicitly an upper bound from static analysis, and every behavioral gap the
adapter papered over is recorded in per-datadir `wrapper-dropped-flags.log`
rather than hidden. The lane is tooling only: it adds no `crates/`, `bin/`,
`scripts/`, or `e2e/` code (its only non-`tools/` changes are the
documentation that indexes and contracts it), consensus and persistence
behavior are unchanged, and node synchronization is affected only in the
sense that a node process is exercised - no sync, validation, or commit
path code is modified.
