# Validation tooling and evidence index

This document provides a single operator-facing entry point to discover,
reproduce, and understand `bitcoin-rs` validation, verification, and differential
evidence lanes.

The implementation of each lane remains owned by its existing scripts, crates,
test suites, and contracts; this index does not create a secondary test runner,
framework, or test-only runtime state.

## Evidence tier distinction

Following the [ecosystem compatibility contract](contracts/ecosystem-compatibility.md)
(`ECO-02`, `ECO-08`, `ECO-09`):

- **Real external-consumer evidence**: An unmodified external program or
  reference implementation exercises `bitcoin-rs` through documented public
  interfaces (P2P wire, JSON-RPC, REST, ZMQ, or public CLI). Only runs with real
  external programs qualify as `externally verified`.
- **In-tree and differential evidence**: Reference test vectors, independent
  library differentials, C++ oracle comparisons, fuzz campaigns, and
  fault-injection suites maintained inside this repository. These prove internal
  correctness and regression defense, reported honestly as `implemented / tested`.

## Evidence lanes summary

Owners, prerequisites, commands, and scope limitations are listed in each section.

| Lane | Evidence status |
|---|---|
| [Live Core P2P](#1-live-bitcoin-core-p2p-and-chain-identity-differential) | Externally verified |
| [Live Core acceptance](#2-live-core-block-and-transaction-acceptance-differential) | Curated cases tested |
| [Core vectors](#3-bitcoin-core-script-and-transaction-vectors) | Script evaluation / tx parsing |
| [Sighash differential](#4-native-sighash-checks-against-independent-implementation) | Implemented / tested |
| [Kernel oracle & parity](#5-libbitcoinkernel-oracle-and-scoped-native-parity) | Tested; scoped differential |
| [Consensus rules](#6-contextual-consensus-rule-tests) | Implemented / tested |
| [Fuzzing & corpus](#7-daily-fuzz-targets-and-qa-assets-corpus-provenance) | Implemented / tested |
| [Crash recovery & reorgs](#8-chainstate-crash-recovery-and-reorg-evidence) | Implemented / tested |
| [Offline comparator](#9-offline-full-validation-comparator) | Harness tested; campaign pending |
| [Ecosystem compatibility](#10-external-ecosystem-compatibility-matrix) | Per-surface evidence |
| [USDT observability](#11-usdt--bpftrace-observability-validation) | ABI tested; live tracing planned |
| [Measured campaign runner & analyzer](#12-measured-campaign-runner-and-analyzer) | Harness tested; campaign pending |

---

## 1. Live Bitcoin Core P2P and chain-identity differential

- **Tier**: Real external-consumer evidence.
- **Contract & clauses**: [`docs/contracts/core-differential.md`](contracts/core-differential.md) (`CORE-01`, `CORE-02`, `CORE-03`, `CORE-05`, `CORE-06`).
- **Owner scripts & suites**:
  - Pinned installer: `scripts/install-bitcoind.sh` (POSIX) / `scripts/install-bitcoind.ps1` (Windows).
  - Test runner: `scripts/run-p2p-core-interop.sh`.
  - Evidence validator: `crates/p2p/tests/core_interop_live.rs` (BIP324 vector provenance in [`crates/p2p/tests/data/bip324/README.md`](../crates/p2p/tests/data/bip324/README.md); AddrMan/ASMap reference fixtures in [`crates/p2p/tests/support/README.md`](../crates/p2p/tests/support/README.md), [`crates/p2p/tests/data/asmap-core-v31.1.README.md`](../crates/p2p/tests/data/asmap-core-v31.1.README.md), [`crates/p2p/tests/data/asmap-linked-ipv4-core-v31.1.README.md`](../crates/p2p/tests/data/asmap-linked-ipv4-core-v31.1.README.md), and the canonical v1 book fixture [`crates/p2p/tests/data/addrman-canonical-v1-shared.json`](../crates/p2p/tests/data/addrman-canonical-v1-shared.json). No historical-schema migration fixtures exist; the pre-release AddrMan freeze is owned by [`docs/policies/p2p-compatibility.md`](policies/p2p-compatibility.md) section 7.
- **What is verified**:
  - Pinned Bitcoin Core 31.1 binary downloaded from bitcoincore.org and checked
    against the SHA-256 archive digest pinned in `crates/rpc/core-compat.toml`.
  - Live regtest P2P handshake, IBD sync, compact block relay (BIP152 phases A–C),
    disconnect handling, tip agreement (`getblockcount`, `getbestblockhash`,
    `getblockchaininfo.{chain,blocks}`), and direct wire comparison of proactive
    `inv`, `headers`, and high-bandwidth `cmpctblock` announcements across a reorg.
  - BIP324 v2 sync in both directions: one fresh node dials Core and Core dials
    another, each reporting `v2` with the same session id on both ends and
    answering Core's ping. The main node stays on v1.
  - Compact-block relay counts are diagnostic log-derived counters per `ECO-09`.
- **Reproduce**:
  ```sh
  # 1. Provision pinned Bitcoin Core 31.1 binary
  scripts/install-bitcoind.sh --print-path

  # 2. Build quickstart portable node binary
  cargo build --locked -p bitcoin-rs --profile quickstart --no-default-features --features fjall,zmq

  # 3. Execute live differential interop run
  scripts/run-p2p-core-interop.sh \
    --bitcoind-command "$(scripts/install-bitcoind.sh --print-path)" \
    --bitcoin-rs-command target/quickstart/bitcoin-rs \
    --workdir target/core-differential/run \
    --evidence target/core-differential/evidence.json

  # 4. Verify schema and compact block relay assertions
  P2P_CORE_INTEROP_EVIDENCE=target/core-differential/evidence.json \
    cargo test --locked -p bitcoin-rs-p2p --test core_interop_live -- --ignored
  ```
- **Artifacts**: CI retains `target/core-differential/*.log` and `evidence.json`
  in the `core-differential-<run_attempt>` artifact for 7 days.

---

## 2. Live Core block and transaction acceptance differential

- **Tier**: In-tree live-reference differential evidence, not external-consumer interoperability verification. The in-repo `ProcessNode` harness invokes both nodes' public RPCs; the unmodified pinned Bitcoin Core binary acts as an independent behavioral oracle.
- **Contract & clauses**: [`docs/contracts/core-differential.md`](contracts/core-differential.md) (`CORE-04`).
- **Owner suites**: `e2e/tests/acceptance.rs` using `e2e::differential` and `ProcessNode`.
- **What is verified**:
  - Sends identical serialized blocks (`submitblock`) and transactions
    (`testmempoolaccept`) to an isolated `bitcoind` (Core 31.1) and `bitcoin-rs`
    instance on regtest.
  - Verifies identical accept/reject decisions across coinbase-only blocks, bad
    merkle roots, multiple coinbases, short scriptSig, excessive values, BIP34
    height mismatches, MTP boundaries, mature spends, immature coinbase spends,
    duplicate inputs, overspends, and relative lock times.
  - Broader differential fuzzing and rule coverage are future work, not currently
    implemented.
- **Reproduce**:
  ```sh
  # Install the pinned live Bitcoin Core reference.
  scripts/install-bitcoind.sh --print-path

  # Build and select the exact bitcoin-rs binary being compared.
  cargo build --locked --release -p bitcoin-rs
  BITCOIN_RS_NODE="$PWD/target/release/bitcoin-rs" \
    BITCOIN_RS_REFERENCE_BITCOIND="$(scripts/install-bitcoind.sh --print-path)" \
    cargo test --locked -p bitcoin-rs-e2e --test acceptance
  ```
- **Artifacts**: `acceptance-*.json` files recorded under the test process evidence
  directory.

---

## 3. Bitcoin Core script and transaction vectors

- **Tier**: In-tree reference vector evidence.
- **Owner suites**:
  - `crates/script/tests/core_vectors.rs`: Bitcoin Core `script_tests.json`,
    `tx_valid.json`, and `tx_invalid.json` script-verification columns.
  - `crates/consensus/tests/vectors.rs`: Transaction-vector loading/deserialization,
    script flag parsing, and legacy sighash checks.
- **What is verified**:
  - The script suite evaluates runnable rows with the native interpreter and
    pins executed, skipped, and mismatch counts. Its transaction columns check
    script verification, not full transaction validity; `BADTX` rows requiring
    non-script `CheckTransaction` checks are skipped.
  - The consensus suite loads `tx_valid.json` and `tx_invalid.json` and checks
    transaction deserialization. It does not compare consensus-validator
    accept/reject decisions with those vectors' expected validity.
- **Reproduce**:
  ```sh
  cargo test --locked -p bitcoin-rs-script --test core_vectors
  cargo test --locked -p bitcoin-rs-consensus --test vectors
  ```

---

## 4. Native sighash checks against independent implementation

- **Tier**: In-tree differential evidence.
- **Owner suites**:
  - `crates/consensus/tests/shared_sighash.rs`: Native sighash verified against
    the independent `rust-bitcoin` engine (`bitcoin::sighash::SighashCache`).
  - `crates/script/tests/proptest.rs`: Property-based fuzzing using `rust-bitcoin`
    sighash and Schnorr signing as the oracle.
  - `crates/primitives/tests/differential.rs`: Core `sighash.json` legacy vectors.
  - `crates/primitives/tests/bip_vectors.rs`: Authoritative BIP143 and BIP341 vectors (provenance in [`crates/primitives/tests/vectors/PROVENANCE.md`](../crates/primitives/tests/vectors/PROVENANCE.md)).
- **What is verified**:
  - Exact digest equality across all sighash flags (`SIGHASH_ALL`, `NONE`, `SINGLE`,
    `ANYONECANPAY`, `DEFAULT`) for legacy, BIP143 (SegWit v0), and BIP341 (Taproot).
- **Reproduce**:
  ```sh
  cargo test --locked -p bitcoin-rs-consensus --test shared_sighash
  cargo test --locked -p bitcoin-rs-script --test proptest
  cargo test --locked -p bitcoin-rs-primitives --test differential
  cargo test --locked -p bitcoin-rs-primitives --test bip_vectors
  ```

---

## 5. libbitcoinkernel oracle and scoped native parity

- **Tier**: In-tree oracle & differential evidence.
- **Related contract**: [`docs/contracts/validation-default.md`](contracts/validation-default.md) (`Proven by` evidence; no `VAL-02` clause is defined).
- **Owner suites**:
  - `crates/consensus/tests/kernel_vector_parity.rs`: Core transaction vectors
    evaluated through `libbitcoinkernel`'s `verify_tx_scripts` against expected
    script verdicts. `BADTX` rows are excluded because this entry point does not
    perform non-script transaction checks. This is a kernel-versus-vector oracle,
    not a native-versus-kernel differential over the full corpus.
  - `crates/consensus/tests/kernel_block_parity.rs`: Kernel and native interpreter
    acceptance/rejection checks across all six committed mainnet spend-class
    fixtures (`legacy_p2pk`, `legacy_p2pkh`, `p2sh_spend`, `segwit_v0_spend`,
    `taproot_keypath_spend`, `taproot_scriptpath_spend`), all carrying
    `interpreter_parity: true`, plus a Taproot script-path non-vacuity check
    (fixture provenance in [`crates/consensus/tests/vectors/scripts/README.md`](../crates/consensus/tests/vectors/scripts/README.md)).
- **Prerequisites**: `libboost-dev`, `cmake`, and C++ compiler toolchain.
- **Reproduce**:
  ```sh
  cargo test --locked -p bitcoin-rs-consensus --features kernel \
    --test kernel_vector_parity --test kernel_block_parity -- --nocapture
  ```

---

## 6. Contextual consensus-rule tests

- **Tier**: In-tree consensus verification.
- **Owner suites**:
  - `crates/chain/src/header_sync.rs` (`contextual_header_tests`): Contextual nBits
    difficulty adjustments, Median Time Past (MTP), BIP94 timewarp, and version floors.
  - `crates/consensus/src/verify_block.rs`: Enforces BIP30 duplicate txid checks,
    BIP34 coinbase height, BIP68 relative locktimes, BIP141 SegWit commitments,
    and block weight limits.
  - `crates/chainstate/tests/unit/apply/persistence_tests.rs`: Mutation failure
    boundaries, undo persistence atomicity, and BIP30 overwrite undo coin restoration.
- **Reproduce**:
  ```sh
  cargo test --locked -p bitcoin-rs-chain header_sync::contextual_header_tests
  cargo test --locked -p bitcoin-rs-consensus verify_block::tests
  cargo test --locked -p bitcoin-rs-chainstate --lib persistence_tests
  ```

---

## 7. Daily fuzz targets and QA-assets corpus provenance

- **Tier**: In-tree fuzzing and corpus regression.
- **Contract & clauses**: [`docs/contracts/qa-corpus.md`](contracts/qa-corpus.md) (`QAC-01`..`QAC-05`).
- **Provenance record**: [`fuzz/CORPUS_PROVENANCE.md`](../fuzz/CORPUS_PROVENANCE.md).
- **External integration in progress**: Adding bitcoin-rs as a differential
  fuzzing module in bitcoinfuzz, tracked in
  [bitcoinfuzz/bitcoinfuzz#662](https://github.com/bitcoinfuzz/bitcoinfuzz/issues/662).
  This integration effort is separate from the existing in-tree fuzz campaigns
  and is not yet reported as completed external verification.
- **Campaign prerequisites**: Linux shell tools (`jq`, `sha1sum`), `cargo-fuzz`,
  and nightly Rust with `llvm-tools-preview`. Keep the writable companion corpus
  checkout on the same filesystem as this repository; the campaign minimizes it.
- **Owner scripts & suites**:
  - Seed importer: `scripts/import-qa-assets.sh`, `scripts/import-reference-corpora.sh`.
  - Seed validator: `scripts/validate-corpus-seeds.sh`.
  - Fuzz runner: `scripts/run-fuzz-campaign.sh`.
  - Codec regression test: `crates/primitives/tests/differential.rs` (`QAC-05`).
- **What is verified**:
  - Seeds imported from `rust-bitcoin/qa-assets`, `bitcoin/bitcoin`, and `btcsuite/btcd`
    feed fuzz targets (`p2p_message`, `block_validate`, `tx_validate`, `script_eval`, `utxo_snapshot`).
  - Seed validator `scripts/validate-corpus-seeds.sh` checks the corpus filesystem only:
    every entry is a non-symlink regular file named by its own SHA-1 digest, no larger
    than `FUZZ_MAX_SEED_BYTES`, with a positive total count and modes normalized to
    `0644` (the `-n`/`-b` flood budget applies only when passed). It performs no codec,
    verdict, or consensus check and exits nonzero on the first refusal.
  - Native consensus codec round-trip (`crates/primitives/tests/differential.rs`) checks
    every corpus seed against pinned verdicts (`accepted` with byte-identical re-encoding,
    or typed `rejected:<kind>`) without untyped failures or panics, but only when the
    corpus checkout exists and carries `verdicts.json`: an absent corpus skips loudly,
    and an absent `verdicts.json` degrades to a verdict-shape check with a warning.
- **Reproduce**:
  ```sh
  # Native codec roundtrip check over corpus seeds:
  BITCOIN_RS_FUZZ_CORPUS=../bitcoin-rs-fuzz-corpus/corpus \
    cargo test --locked -p bitcoin-rs-primitives --test differential

  # Run a bounded fuzz campaign with target, seconds, corpus, and output paths:
  ./scripts/run-fuzz-campaign.sh \
    p2p_message 60 \
    ../bitcoin-rs-fuzz-corpus/corpus/p2p_message \
    target/fuzz-campaign/p2p_message
  ```

---

## 8. Chainstate crash recovery and reorg evidence

- **Tier**: In-tree durability and recovery verification.
- **Contract & clauses**: [`docs/contracts/recovery.md`](contracts/recovery.md).
- **Owner suites**:
  - `crates/chainstate/tests/unit/recovery_marker_order_tests.rs`: Recovery marker sequencing.
  - `crates/chainstate/tests/unit/durable_replay_tests.rs`: Replay from durable commit points.
  - `crates/chainstate/tests/unit/assumeutxo_recovery_tests.rs`: Simulates process
    termination (SIGKILL) mid-import, mid-activation, and mid-validation; verifies
    lost failure receipt retention, durable head checkpoint recovery, and below-base reorgs (Core v2 snapshot fixture provenance in [`crates/utxo/tests/fixtures/core-v2/README.md`](../crates/utxo/tests/fixtures/core-v2/README.md); offline snapshot inspection CLI in [`tools/snapshot/README.md`](../tools/snapshot/README.md)).
  - `crates/storage/tests/durable_head_store.rs`: Atomic head row commits and corruption refusal.
  - `crates/storage/src/checkpoint/tests.rs`: Checkpoint generation publication failpoints and retention.
  - `e2e/tests/reorg.rs`, `e2e/tests/reorg_state.rs`: Reorg tip rewinds, invalid higher-work branches,
    and mempool restoration (process-test mapping in [`e2e/REORG-COVERAGE.md`](../e2e/REORG-COVERAGE.md)).
- **Feature requirement**: The AssumeUTXO recovery unit module is gated by
  `fjall`; without it, that filter selects no tests.
- **Host prerequisite (AssumeUTXO non-UTF-8 snapshot test)**:
  `e2e/tests/assumeutxo.rs::invalid_core_snapshots_fail_without_activating`
  requires `/tmp` to accept arbitrary non-NUL byte filenames for its Unix
  fixture. The test owns a temporary directory under `/tmp` containing
  `core-\xff.dat`; the UTF-8 `core200.dat` symlink stays in the node datadir,
  and the RPC receives `{"path":"core200.dat"}`. It copies the snapshot to the
  target, removes the original, and creates the symlink rather than renaming
  across potentially different filesystems. The owned target directory is
  removed at test end or on an early error. This leaves the node datadir and
  global `TMPDIR` on their configured disk-backed filesystem, even if that
  filesystem rejects non-UTF-8 entry names. The former rename-in-datadir
  fixture could fail with `EILSEQ` (92) before RPC; that failure was not JSON
  serialization. A byte-capable `/tmp` remains a host prerequisite; record an
  incapable lane as `BLOCKED` rather than skipping or weakening the scenario.
- **Reproduce**:
  ```sh
  cargo test --locked -p bitcoin-rs-chainstate --lib recovery_marker_order_tests
  cargo test --locked -p bitcoin-rs-chainstate --lib durable::tests
  cargo test --locked -p bitcoin-rs-chainstate \
    --features fjall --lib assumeutxo::tests::recovery
  cargo test --locked -p bitcoin-rs-storage --test durable_head_store
  cargo test --locked -p bitcoin-rs-e2e --test reorg
  ```

---

## 9. Offline full-validation comparator

- **Tier**: In-tree benchmark / parity harness.
- **Contract & clauses**: [`docs/benchmarks/offline-full-validation.md`](benchmarks/offline-full-validation.md),
  [`docs/contracts/campaign-corpora.md`](contracts/campaign-corpora.md) (`CORP-01`..`CORP-05`).
- **Owner scripts & tools**:
  - Harness: `tools/benchmark-campaign/offline_full_validation.py`.
  - Harness tests: `tools/benchmark-campaign/test_offline_full_validation.py`.
  - Corpus exporter: `tools/campaign-corpus/corpus.py` (`export` pulls the frozen
    archive from a Core node REST interface, `verify` rebinds an archive to its manifest).
- **What is verified**:
  - Executes the SHA-256 pinned `core.binary` and `candidate.binary` programs named
    in `offline-full-validation-config-v1` on the same hash-pinned Core-framed
    block archive (`blk*.dat`). The harness performs no Core version check of its
    own, so for a Core 31.1 arm point `core.binary` at the
    `scripts/install-bitcoind.sh --print-path` output (by default
    `${HOME}/bitcoin-core-31.1/bin/bitcoind` unless `BITCOIND_PREFIX` is set).
    Each arm runs its verified
    copy at `<root>/<NN>-<role>/node-under-test` (for example `00-core/node-under-test`),
    which is what the `{binary}` placeholder in each arm command expands to.
  - Asserts identical certified end state (height, best block hash, UTXO count,
    total amount, `MuHash3072`, `hash_serialized_3`) and compares full validation timing.
  - Unit tests prove custody checks, file validation, and percentile summaries in CI;
    live C150 / Cmodern full-mainnet execution is **planned / not yet executed**.
- **Reproduce**:
  ```sh
  # Run comparator harness behavioral tests (Python 3.13):
  python3 tools/benchmark-campaign/test_offline_full_validation.py
  python3 tools/campaign-corpus/test_corpus.py

  # Export the frozen input archive from a Core node REST interface
  # (fetches /rest/blockhashbyheight/<height>.hex and /rest/block/<hash>.bin):
  python3 tools/campaign-corpus/corpus.py export --rest-url <host:port> \
    --corpus-id C150 --archive <archive-path> --manifest <manifest-path>
  ```

---

## 10. External ecosystem compatibility matrix

- **Tier**: Strategic compatibility tracking.
- **Contract & matrix**: [`docs/contracts/ecosystem-compatibility.md`](contracts/ecosystem-compatibility.md) (`ECO-08`),
  [`docs/api/ecosystem-compat.toml`](api/ecosystem-compat.toml).
- **Status overview**:
  - **Externally verified**: P2P v1 wire protocol, Compact block relay (BIP152),
    Compact block filters (BIP157/BIP158; runner in [`tools/compact-filter-interop/README.md`](../tools/compact-filter-interop/README.md)), BIP324 v2 transport.
  - **Partially compatible**: Peer lifecycle and address management (recorded deviations in P2P policy).
  - **Implemented**: JSON-RPC, REST, ZMQ notifications, Esplora-compatible API (Compose example in [`tools/btc-mempool-explorer/README.md`](../tools/btc-mempool-explorer/README.md)), GetBlockTemplate,
    block submission, USDT tracepoints.
  - **Experimental**: BIP352 Silent Payments (`getblocktweaks`, [`docs/silent-payments.md`](silent-payments.md)); the Stratum V2 Template Distribution adapter, a regtest-only example
    outside the workspace (not a compatibility commitment, no production pool
    qualification; see [`tools/stratum-sv2/README.md`](../tools/stratum-sv2/README.md)); and the standalone in-process LDK L1 adapter ([`tools/ldk/README.md`](../tools/ldk/README.md)).
  - **Intentionally unsupported**: Core IPC adapters.
  - **Lightning interop (evidence-gated, not a lane verdict)**: LND `v0.21.4-beta` five cells `not exercised`: the only record (`parent-live-4`) is unretained gitignored scratch (61-dirty source, `.outline` runner copy diverging from the tracked script, unverified manifest signature, no fresh Core comparison; `docs/lightning-interop-matrix.md` §2–§3.1). CLN `v26.06.9` startup `failed` in retained qualified `run-2` (`.outline/evidence/lightning-live-cln/run-2/evidence.json`): version gate refusal `1400` below `220000` with Core 31.1 reaching `getinfo` ready, other 4 cells `not exercised` on causal startup, `getblockfrompeer` probed as `rs=method_not_found` and `core=rpc_error` (fallback only), source HEAD `aab50bd64` with 7 dirty entries and 758 inputs (`stale_allowed:false`), node `48129ac5…`, runner frozen `86eba76…` with parent job `bg_543` checksum before plus `bash -n` plus private `ShellCheck` plus real campaign plus checksum after in one chain with exit `0` in `.outline/evidence/lightning-live-cln/run-2/verification.json`, `run-1` raw only with no claim (same matrix section).
- **Reproduction & audit**:
  - Audit status strings against the canonical matrix:
    ```sh
    # Inspect rows and status vocabulary
    cat docs/api/ecosystem-compat.toml
    ```
  - Reproduce the Lightning evidence record (wall-clock bounded; parent runs builds/gates once):
    ```sh
    # CLN live cell with pinned artifacts; see docs/lightning-interop-matrix.md §4 for the exact command
    timeout --signal=TERM --kill-after=30 900 bash scripts/verify-lightning-interop.sh --target cln \
      --bitcoin-rs-bin <path-to-built-bitcoin-rs> \
      --bitcoind-bin <path-to-bitcoin-core-31.1> \
      --cln-bin <extract-dir>/usr/bin/lightningd \
      --cln-release-archive <dir>/clightning-v26.06.9-Ubuntu-26.04-amd64.tar.xz \
      --cln-library-path <dir>/libpq-probe/root/usr/lib/x86_64-linux-gnu
    ```

---

## 11. USDT / bpftrace observability validation

- **Tier**: In-tree probe ABI inspection; live tracing planned.
- **Documentation**: [`docs/tracing.md`](tracing.md).
- **Owner definitions & tests**:
  - Probe definition table: `crates/consensus/probes.d`.
  - ELF note validator: `crates/consensus/tests/sdt_notes.rs`.
  - Sample probe script: `docs/tracing/smoke.bt` (adapted from Bitcoin Core's `contrib/tracing`).
- **What is verified**:
  - Asserts presence and signatures of static USDT probe notes (`net`, `validation`,
    `mempool`) in the compiled binary matching Bitcoin Core's probe ABI.
  - Live external tracing via `bpftrace`/BCC remains planned as an ecosystem consumer.
- **Reproduce**:
  ```sh
  # Verify enabled probe SDT notes in the test binary (or set SDT_ELF=$PWD/target/release/bitcoin-rs):
  cargo test --locked -p bitcoin-rs-consensus \
    --features usdt --test sdt_notes

  # Separately verify that a feature-off build contains no probe notes:
  cargo test --locked -p bitcoin-rs-consensus \
    --no-default-features --test sdt_notes
  ```

---

## 12. Measured campaign runner and analyzer

- **Tier**: In-tree benchmark campaign harness.
- **Contract & guide**: [`docs/benchmarks/measured-campaign.md`](benchmarks/measured-campaign.md),
  [`docs/benchmarks/README.md`](benchmarks/README.md),
  [`docs/contracts/hot-path-attribution.md`](contracts/hot-path-attribution.md) (`HPA-10`, `HPA-13`).
- **Owner scripts & tools**:
  - Runner: `tools/benchmark-campaign/measured_runner.py`.
  - Analyzer: `tools/benchmark-campaign/measured_analyze.py`.
  - Synthetic smoke probe: `tools/benchmark-campaign/test_measured_campaign.py`.
  - Shared counted sampler: `tools/benchmark-support/measured_samples.rs`.
- **What is verified**:
  - Validates complete campaign registration JSON inputs, five-tree source/bench/lock digests, build receipts, baseline evidence documents, and live `/proc/cpuinfo` processor affinity and model bindings before any benchmark launch (`validate`, `plan`, `run`).
  - Parses Criterion `sample.json` files, `MRP_COUNTED_SAMPLE` measured-work stdout lines, and T2/T3 standalone node JSONL stdout into fail-closed per-target verdicts (`INCONCLUSIVE`, `REGRESSION`, `NON_REGRESSION_EVIDENCED`, `AT_FLOOR`).
  - The offline synthetic probe verifies schema, parser, self-binding, and statistical adversaries on temporary stub fixtures without launching any benchmark process; a passing probe does not constitute a registered campaign or performance acceptance.
- **Reproduce**:
  ```sh
  # Run offline hermetic synthetic smoke probe (launches no workloads):
  uv run --offline --no-project --script tools/benchmark-campaign/test_measured_campaign.py
  ```

## 12a. Filesystem-aware Linux measurement boundary

- **Tier**: In-tree benchmark campaign harness (diagnostic, not a product-cell qualification).
- **Owner scripts & tools**:
  - Scope owner: `tools/benchmark-campaign/filesystem.py` (one owner for mount/filesystem/backing-counter scope plus read-only cumulative counter samples; no project or toolchain migration, stdlib only).
  - Contract tests: `tools/benchmark-campaign/test_filesystem.py`.
  - Consumer: the private index-write-attribution harness delegates its former mountinfo/sysfs/diskstats lookup, counter reads, and sector deltas to this owner; the harness keeps its own strict qualification gate.
- **Boundary**: one target filesystem per run. Apparent bytes, allocated file bytes, per-process I/O counters, and attributable host block-device writes are reported separately and never merged. Allocated-file measurement stays in the existing Rust `storage-footprint` tool and is not duplicated here.
- **Supported scopes**:
  - `regular_block_device`: the mount resolves to one bare block device with a readable kernel sectors-written counter. Available (host-wide for that device).
  - `zfs_pool`: ZFS datasets report pool-wide accounting that cannot isolate one filesystem, so the scope is unavailable; no pool total is converted into a per-filesystem value.
  - `composite_anonymous`: overlay/tmpfs/ramfs/network/fuse/9p/virtiofs mounts (and other major-0 mounts) expose no per-filesystem block counter. Unavailable.
  - `ambiguous_multi_device`: btrfs or any stacked (mapped) device over one or more underlying devices. A mapped device is never assumed to be a single disk; underlying counters are listed, never summed. Unavailable.
  - `unavailable`: no mount entry, missing counter file or permission, unparsable counter, counter wrap/reset/recreation, or a `--device` override that names anything other than the mount's own `MAJ:MIN` (operator assertion alone is not proof of backing). Unavailable is reported with an explicit reason, never as zero.
- **Mechanisms checked** (read-only; the owner spawns no subprocess): `/proc/self/mountinfo` with octal-escape decoding and longest-prefix mount selection, the chosen device's `/sys/dev/block/<MAJ:MIN>/stat` sectors-written counter (kernel 512-byte block-layer unit regardless of filesystem block size), `/proc/diskstats` sectors-written recorded as a diagnostic alongside the sysfs counter (never cross-validated against it), `slaves`/`holders` topology, and `shared-mount` plus informational queue/model attributes recorded as diagnostics. Exactly one device counter is ever read per scope: a partition's own counter, never the parent disk added to it.
- **Honest limits**: the counter is host-wide for its device (every writer included); the collector never attests isolation and never qualifies a run. Counter wrap/reset yields unavailable, not a negative or zero delta. Per-filesystem physical writes are never fabricated from allocation counters, per-process I/O counters, or pool totals.
- **Parent live observation** (bounded, read-only):
  ```sh
  # Identify the scope behind a scratch path:
  python3 tools/benchmark-campaign/filesystem.py identify --path /srv/scratch
  # Identify and take one cumulative sample:
  python3 tools/benchmark-campaign/filesystem.py sample --path /srv/scratch
  ```
