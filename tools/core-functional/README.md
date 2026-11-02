# Core functional compatibility lane

Runs Bitcoin Core v31.1's Python functional test suite (`test/functional`)
against the bitcoin-rs node binary, without modifying either side: the suite
is extracted from a pinned Core tag into the gitignored scratch area, and the
node is presented to the framework through an argv/config/cookie adapter that
the framework spawns instead of `bitcoind`.

Everything in this directory is external validation tooling. Nothing here
changes consensus, persistence, or node behavior; the node is only invoked.

## Status

**No measured results yet.** The lane has been built and smoke-tested for
plumbing only (script syntax, extraction, wrapper translation, fail-safe
paths). No test has been run to completion against a built bitcoin-rs binary
in this phase, so no pass/skip/fail counts exist and no compatibility claim is
made or implied. The first real run's `report.json`/`report.md` (written by
`run.sh`) is the evidence baseline.

Known expectation, not a claim: tests whose setup depends on Core-only
behavior the adapter deliberately drops (e.g. `-loadblock=`, `-includeconf=`,
net permission flags in `rpc_whitelist.py`, the Core-format premined chain
cache that non-clean-chain tests copy into node datadirs) are expected to
fail honestly rather than be silently accommodated.

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
| `bin/bitcoind-wrapper` | Python adapter exec'd by the framework. Translates Core-style argv to bitcoin-rs flags, derives a supported-only `bitcoin-rs-derived.conf` from the framework's `bitcoin.conf`, and creates the RPC cookie file where the framework reads it (`<datadir>/<chain>/.cookie`), pointing the node at it via `--rpc-cookie`. Unmappable flags/conf keys are dropped and appended as JSON lines to `<datadir>/wrapper-dropped-flags.log`. Silent on stdout/stderr in success paths. Reads `BITCOIN_RS_BIN` (required) and `BITCOIN_RS_EXTRA_ARGS` (optional, appended verbatim). |
| `config.ini` | Template framework config; `run.sh` renders `@CORE_TESTS_DIR@` into the results dir. `ENABLE_BITCOIND=true`, every other component `false` so wallet/cli/zmq-dependent tests take the framework's own skip paths. |
| `shim/sitecustomize.py` | PYTHONPATH startup hook; every patch is an explicitly recorded bitcoin-rs deviation (the file header owns the full detail). The MiniWallet patch is unconditional; the other two each carry a disable env var. Three patches remain: (1) MiniWallet `generate` mines via the implemented `generatetoaddress` instead of the unimplemented `generatetodescriptor` (ADDRESS_OP_TRUE mode only; other modes keep upstream behavior and fail loudly); (2) no-ops the one framework-plumbing RPC the node still lacks, `setmocktime` (no candidate test calls it itself); (3) strips exactly the `stop(wait=0)` teardown form (non-zero waits still fail honestly). The tools PR's fourth patch (client-side `params:{}` and `generatetoaddress` named-object rewrite) and its `syncwithvalidationinterfacequeue` no-op are deleted by this stack's rpc commits: the node now accepts the empty-object params envelope-wide, binds `generatetoaddress(nblocks=, address=, maxtries=)`, and implements `syncwithvalidationinterfacequeue`. No Core code is copied; patches preserve upstream post-conditions where they apply. |
| `run.sh` + `bin/runner.py` | Runner: per-test `python3 <test>.py --configfile <rendered config.ini> --tmpdir <results>/tmp/<test> --cachedir <results>/cache` with the shim on `PYTHONPATH`, cwd `= <dest>/test/functional`. Before the parallel pool starts, runs the extracted tree's `create_cache.py` once, serially, against the shared cachedir (Core's own `test_runner.py` pattern) so parallel jobs never race to build the cache; the framework skips mining when the cache node dir already exists, so pre-seeded caches are reused. Each test runs as its own process group; a timeout kills the whole group so node processes a timed-out test spawned cannot linger and hold ports. Classifies 0=PASS, 77=SKIP, else=FAIL (timeout tracked separately). Fails fast (exit 2, before running anything) when `BITCOIN_RS_BIN` is unset/missing. Records per-test exit code, duration, framework-log tail, and captured stdout/stderr tails in `report.json` (a relative `--results-dir` is resolved, since tests run with a different cwd). |
| `tests/clean-candidates.txt` | The 46 tests selected by static RPC-dependency analysis at derivation time: an upper bound on candidates, not pass claims. |

## Wrapper translation table

Verified against `crates/node/src/options.rs` and `bin/bitcoin-rs/src/config.rs`
(`parse_for_network`): unknown conf keys are ignored, known keys parse
strictly, `[<network>]` sections apply only when `--network` matches, and CLI
outranks conf. Mapped Core flag -> bitcoin-rs flag (both `-flag=v` and
`-flag` forms):

| Core | bitcoin-rs |
|------|------------|
| `-datadir=X` | `--data-dir=X` (framework writes `X/bitcoin.conf`; adapter derives `X/bitcoin-rs-derived.conf` via `--bitcoin-conf`) |
| `-regtest` / `-testnet` / `-testnet4` / `-signet` / `-chain=X` / `-main` | `--network=regtest / testnet3 / testnet4 / signet / mainnet / X` |
| `-bind=IP:PORT` | `--p2p-listen=IP:PORT` (bare `-bind=IP` gains the effective port from `port=`; binds with `=onion` qualifiers are dropped) |
| `port=P` (conf/argv, when no explicit bind) | `--p2p-listen=0.0.0.0:P` |
| `-nolisten` / `-listen=0` | `listen=0` line in the derived conf (the node maps it to an empty listen set) |
| `-connect=host:port` | `--connect=host:port` (`-connect=0` dropped) |
| `-v2transport=B` | `--v2transport=B` |
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
i2pacceptincoming, listen`. `rpcuser`/`rpcpassword`/`rpccookiefile` become the
cookie file the adapter writes (see below). Everything else - including the
framework's `server, keypool, discover, fixedseeds, listenonion, peertimeout,
natpmp, fallbackfee, rpcservertimeout, rpcdoccheck, rpcthreads,
maxconnections, par, shrinkdebugfile, unsafesqlitesync, connect=0` and test
flags like `-uacomment, -logtimemicros, -debug, -debugexclude, -wallet*,
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
