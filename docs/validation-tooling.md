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

---

## 1. Live Bitcoin Core P2P and chain-identity differential

- **Tier**: Real external-consumer evidence.
- **Contract & clauses**: [`docs/contracts/core-differential.md`](contracts/core-differential.md) (`CORE-01`, `CORE-02`, `CORE-03`).
- **Owner scripts & suites**:
  - Pinned installer: `scripts/install-bitcoind.sh` (POSIX) / `scripts/install-bitcoind.ps1` (Windows).
  - Test runner: `scripts/run-p2p-core-interop.sh`.
  - Evidence validator: `crates/p2p/tests/core_interop_live.rs`.
- **What is verified**:
  - Pinned Bitcoin Core 31.1 binary downloaded from bitcoincore.org and checked
    against the SHA-256 archive digest pinned in `crates/rpc/core-compat.toml`.
  - Live regtest P2P handshake, IBD sync, compact block relay (BIP152 phases A–C),
    disconnect handling, and tip agreement (`getblockcount`, `getbestblockhash`,
    `getblockchaininfo.{chain,blocks}`).
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
    cargo test -p bitcoin-rs-p2p --test core_interop_live -- --ignored
  ```
- **Artifacts**: CI retains `target/core-differential/*.log` and `evidence.json`
  in the `core-differential-<run_attempt>` artifact for 7 days.

---

## 2. Live Core block and transaction acceptance differential

- **Tier**: Real external-consumer evidence.
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
  cargo build --release -p bitcoin-rs
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
  - `crates/primitives/tests/bip_vectors.rs`: Authoritative BIP143 SegWit vectors.
- **What is verified**:
  - Exact digest equality across all sighash flags (`SIGHASH_ALL`, `NONE`, `SINGLE`,
    `ANYONECANPAY`, `DEFAULT`) for legacy, BIP143 (SegWit v0), and BIP341 (Taproot).
- **Reproduce**:
  ```sh
  cargo test -p bitcoin-rs-consensus --test shared_sighash
  cargo test -p bitcoin-rs-script --test proptest
  cargo test -p bitcoin-rs-primitives --test differential
  cargo test -p bitcoin-rs-primitives --test bip_vectors
  ```

---

## 5. libbitcoinkernel oracle and scoped native parity

- **Tier**: In-tree oracle & differential evidence.
- **Contract & clauses**: [`docs/contracts/validation-default.md`](contracts/validation-default.md) (`VAL-02`).
- **Owner suites**:
  - `crates/consensus/tests/kernel_vector_parity.rs`: Core transaction vectors
    evaluated through `libbitcoinkernel`'s `verify_tx_scripts` against expected
    script verdicts. `BADTX` rows are excluded because this entry point does not
    perform non-script transaction checks. This is a kernel-versus-vector oracle,
    not a native-versus-kernel differential over the full corpus.
  - `crates/consensus/tests/kernel_block_parity.rs`: Kernel acceptance/rejection
    checks on pristine and mutated mainnet transaction fixtures. Direct native
    interpreter parity is limited to fixtures opting into `interpreter_parity`
    (currently Taproot key-path), plus a Taproot script-path non-vacuity check.
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
  cargo test -p bitcoin-rs-chain header_sync::contextual_header_tests
  cargo test -p bitcoin-rs-consensus verify_block::tests
  cargo test --locked -p bitcoin-rs-chainstate --lib persistence_tests
  ```

---

## 7. Daily fuzz targets and QA-assets corpus provenance

- **Tier**: In-tree fuzzing and corpus regression.
- **Contract & clauses**: [`docs/contracts/qa-corpus.md`](contracts/qa-corpus.md) (`QAC-01`..`QAC-05`).
- **Provenance record**: [`fuzz/CORPUS_PROVENANCE.md`](../fuzz/CORPUS_PROVENANCE.md).
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
  - Native consensus codec round-trip enforces that every corpus seed satisfies
    pinned verdicts (`accepted` with byte-identical re-encoding, or typed `rejected:<kind>`)
    without untyped failures or panics.
- **Reproduce**:
  ```sh
  # Native codec roundtrip check over corpus seeds:
  BITCOIN_RS_FUZZ_CORPUS=../bitcoin-rs-fuzz-corpus/corpus \
    cargo test -p bitcoin-rs-primitives --test differential

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
    lost failure receipt retention, durable head checkpoint recovery, and below-base reorgs.
  - `crates/storage/tests/durable_head_store.rs`: Atomic head row commits and corruption refusal.
  - `crates/storage/src/checkpoint/tests.rs`: Checkpoint generation publication failpoints and retention.
  - `e2e/tests/reorg.rs`, `e2e/tests/reorg_state.rs`: Reorg tip rewinds, invalid higher-work branches,
    and mempool restoration.
- **Feature requirement**: The AssumeUTXO recovery unit module is gated by
  `fjall`; without it, that filter selects no tests.
- **Reproduce**:
  ```sh
  cargo test --locked -p bitcoin-rs-chainstate --lib recovery_marker_order_tests
  cargo test --locked -p bitcoin-rs-chainstate --lib durable::tests
  cargo test --locked -p bitcoin-rs-chainstate \
    --features fjall --lib assumeutxo::tests::recovery
  cargo test -p bitcoin-rs-storage --test durable_head_store
  cargo test -p bitcoin-rs-e2e --test reorg
  ```

---

## 9. Offline full-validation comparator

- **Tier**: In-tree benchmark / parity harness.
- **Contract & clauses**: [`docs/benchmarks/offline-full-validation.md`](benchmarks/offline-full-validation.md),
  [`docs/contracts/campaign-corpora.md`](contracts/campaign-corpora.md) (`CORP-01`..`CORP-05`).
- **Owner scripts & tools**:
  - Harness: `tools/benchmark-campaign/offline_full_validation.py`.
  - Harness tests: `tools/benchmark-campaign/test_offline_full_validation.py`.
- **What is verified**:
  - Executes Bitcoin Core 31.1 and `bitcoin-rs` on the same hash-pinned Core-framed
    block archive (`blk*.dat`).
  - Asserts identical certified end state (height, best block hash, UTXO count,
    total amount, `MuHash3072`, `hash_serialized_3`) and compares full validation timing.
  - Unit tests prove custody checks, file validation, and ratio calculation in CI;
    live C150 / Cmodern full-mainnet execution is **planned / not yet executed**.
- **Reproduce**:
  ```sh
  # Run comparator harness behavioral tests (Python 3.13):
  pytest tools/benchmark-campaign/test_offline_full_validation.py
  python3 tools/campaign-corpus/test_corpus.py
  ```

---

## 10. External ecosystem compatibility matrix

- **Tier**: Strategic compatibility tracking.
- **Contract & matrix**: [`docs/contracts/ecosystem-compatibility.md`](contracts/ecosystem-compatibility.md) (`ECO-08`),
  [`docs/api/ecosystem-compat.toml`](api/ecosystem-compat.toml).
- **Status overview**:
  - **Externally verified**: P2P v1 wire protocol, Compact block relay (BIP152).
  - **Partially compatible**: Peer lifecycle and address management (recorded deviations in P2P policy).
  - **Implemented**: JSON-RPC, REST, ZMQ notifications, Esplora-compatible API, GetBlockTemplate,
    block submission, USDT tracepoints.
  - **Intentionally unsupported**: BIP324 (v2 transport), BIP157/BIP158 (block filters), Stratum V2 / Core IPC adapters.
- **Reproduction & audit**:
  - Audit status strings against the canonical matrix:
    ```sh
    # Inspect rows and status vocabulary
    cat docs/api/ecosystem-compat.toml
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
  # Verify enabled probe SDT notes in the compiled binary (Linux ELF64):
  cargo test --locked -p bitcoin-rs-consensus \
    --features usdt --test sdt_notes

  # Separately verify that a feature-off build contains no probe notes:
  cargo test --locked -p bitcoin-rs-consensus \
    --no-default-features --test sdt_notes
  ```
