# Validation tooling and evidence index
Operator entry point to the validation, verification, and differential evidence lanes. Each lane is owned by its scripts, crates, suites, and contracts; this index adds no runner, framework, or test-only state.
## Evidence tier distinction
Per [ecosystem-compatibility](contracts/ecosystem-compatibility.md) (`ECO-02`, `ECO-08`, `ECO-09`): **externally verified** means an unmodified external program exercises `bitcoin-rs` via public P2P/RPC/REST/ZMQ/CLI. **implemented / tested** means in-tree reference vectors, differentials, oracles, fuzz, and fault-injection suites.
## Evidence lanes summary
| Lane | Evidence status |
| --- | --- |
| [Live Core P2P](#1-live-bitcoin-core-p2p-and-chain-identity-differential) | Externally verified |
| [Live Core acceptance](#2-live-core-block-and-transaction-acceptance-differential) | Curated cases tested |
| [Core vectors](#3-bitcoin-core-script-and-transaction-vectors) | Script evaluation / tx parsing |
| [Sighash differential](#4-native-sighash-checks-against-independent-implementation) | Implemented / tested |
| [Kernel oracle & parity](#5-libbitcoinkernel-oracle-and-scoped-native-parity) | Tested; scoped differential |
| [Consensus rules](#6-contextual-consensus-rule-tests) | Implemented / tested |
| [Fuzzing & corpus](#7-daily-fuzz-targets-and-qa-assets-corpus-provenance) | Implemented / tested |
| [Crash recovery & reorgs](#8-chainstate-crash-recovery-and-reorg-evidence) | Implemented / tested |
| [Ecosystem compatibility](#9-external-ecosystem-compatibility-matrix) | Per-surface evidence |
| [USDT observability](#10-usdt--bpftrace-observability-validation) | ABI tested; live tracing planned |
| [Core functional suite](#11-core-functional-suite-against-the-node-binary) | Measured baseline: 8 pass / 5 skip / 33 fail of 46 selected |
## 1. Live Bitcoin Core P2P and chain-identity differential
Tier: externally verified. Contract: [core-differential](contracts/core-differential.md) (`CORE-01`, `CORE-02`, `CORE-03`, `CORE-05`, `CORE-06`). Owners: `scripts/install-bitcoind.sh` (`scripts/install-bitcoind.ps1` on Windows), `scripts/run-p2p-core-interop.sh`, `crates/wire/tests/core_interop_live.rs`. Fixtures: BIP324 vectors `crates/wire/tests/data/bip324/README.md`; AddrMan/ASMap `crates/wire/tests/support/README.md`, `crates/wire/tests/data/asmap-core-v31.1.README.md`, `crates/wire/tests/data/asmap-linked-ipv4-core-v31.1.README.md`; no historical-schema migration fixtures; pre-release AddrMan freeze: [p2p-compatibility](policies/p2p-compatibility.md) section 7. Verifies pinned Core 31.1 (SHA-256 in `crates/serving/core-compat.toml`) regtest handshake, IBD, BIP152 A-C, and tip agreement (`getblockcount`, `getbestblockhash`, `getblockchaininfo.{chain,blocks}`). Also verifies direct `inv`/`headers`/`cmpctblock` wire comparison across a reorg and bidirectional BIP324 v2 (main node stays v1) with Core ping replies. Compact-block relay counts are diagnostic per `ECO-09`.
```sh
scripts/install-bitcoind.sh --print-path && cargo build --locked -p bitcoin-rs --profile quickstart --no-default-features --features zmq
scripts/run-p2p-core-interop.sh --bitcoind-command "$(scripts/install-bitcoind.sh --print-path)" --bitcoin-rs-command target/quickstart/bitcoin-rs --workdir target/core-differential/run --evidence target/core-differential/evidence.json
P2P_CORE_INTEROP_EVIDENCE=target/core-differential/evidence.json cargo test --locked -p bitcoin-rs-wire --test suite core_interop_live:: -- --ignored
```
Artifacts: CI retains `target/core-differential/*.log`, `evidence.json` in `core-differential-<run_attempt>` for 7 days.
## 2. Live Core block and transaction acceptance differential
Tier: in-tree live-reference differential (in-repo `ProcessNode` drives both public RPCs; unmodified pinned Core is the behavioral oracle), not external-consumer verification. Contract: [core-differential](contracts/core-differential.md) (`CORE-04`). Owners: `e2e/tests/acceptance.rs`, `e2e::differential`, `ProcessNode`. Verifies identical accept/reject on regtest for coinbase-only blocks, bad merkle roots, multiple coinbases, short scriptSig, and excessive values. Also covers BIP34 height mismatches, MTP boundaries, mature/immature spends, duplicate inputs, overspends, and relative locktimes (`submitblock`, `testmempoolaccept`). Broader fuzzing/rule coverage is not implemented.
```sh
scripts/install-bitcoind.sh --print-path && cargo build --locked --release -p bitcoin-rs
BITCOIN_RS_NODE="$PWD/target/release/bitcoin-rs" BITCOIN_RS_REFERENCE_BITCOIND="$(scripts/install-bitcoind.sh --print-path)" cargo test --locked -p bitcoin-rs-e2e --test suite acceptance::
```
Artifacts: `acceptance-*.json` under the test process evidence directory.
## 3. Bitcoin Core script and transaction vectors
Tier: in-tree reference vector evidence. Owners: `crates/consensus/tests/script_core_vectors.rs` (`script_tests.json`, `tx_valid.json`, `tx_invalid.json` script-verification columns). Its runnable rows are pinned as executed/skipped/mismatch. Its tx columns check script verification only, and `BADTX` non-script rows are skipped. The second owner is `crates/consensus/tests/vectors.rs`: vector loading/deserialization, script flag parsing, and legacy sighash, with no accept/reject comparison against expected validity.
```sh
cargo test --locked -p bitcoin-rs-consensus --test suite core_vectors:: && cargo test --locked -p bitcoin-rs-consensus --test suite vectors::
```
## 4. Native sighash checks against independent implementation
Tier: in-tree differential evidence. Owners: `crates/consensus/tests/shared_sighash.rs` (native vs `rust-bitcoin` `sighash::SighashCache`), `crates/consensus/tests/script_proptest.rs` (`rust-bitcoin` sighash/Schnorr oracle), `crates/consensus/tests/primitives_differential.rs` (`sighash.json` legacy vectors), `crates/consensus/tests/primitives_bip_vectors.rs` (BIP143/BIP341; provenance `crates/consensus/tests/vectors/sighash-vector-provenance.md`). Verifies exact digest equality for `SIGHASH_ALL/NONE/SINGLE/ANYONECANPAY/DEFAULT` across legacy, BIP143, BIP341.
```sh
cargo test --locked -p bitcoin-rs-consensus --test suite shared_sighash:: && cargo test --locked -p bitcoin-rs-consensus --test suite proptest::
cargo test --locked -p bitcoin-rs-consensus --test suite differential:: && cargo test --locked -p bitcoin-rs-consensus --test suite bip_vectors::
```
## 5. libbitcoinkernel oracle and scoped native parity
Tier: in-tree oracle and differential evidence. Related: [validation-default](contracts/validation-default.md) (`VAL-02` proof boundaries). Owners: `crates/consensus/tests/kernel_vector_parity.rs` (Core vectors via `verify_tx_scripts`; `BADTX` excluded; kernel-vs-vector oracle, not native-vs-kernel over the full corpus). Second owner: `crates/consensus/tests/kernel_block_parity.rs` (kernel vs native accept/reject on six mainnet fixtures `legacy_p2pk/p2pkh`, `p2sh_spend`, `segwit_v0_spend`, `taproot_keypath/scriptpath_spend`, all `interpreter_parity: true`, plus Taproot script-path non-vacuity; provenance `crates/consensus/tests/vectors/scripts/README.md`). Third owner: `crates/consensus/tests/kernel_boundary_parity.rs` (native vs kernel on synthetic consensus-limit boundaries: 10000-byte script, 201 ops, 520-byte push, 1000-deep stack, 20-key multisig, taproot control-block size and annex shapes, nonstandard-but-valid NOP1, OP_CODESEPARATOR). Prerequisites: `libboost-dev`, `cmake`, C++ toolchain.
```sh
cargo test --locked -p bitcoin-rs-consensus --features kernel --test suite -- kernel_block_parity:: kernel_boundary_parity:: kernel_vector_parity:: --nocapture
```
## 6. Contextual consensus-rule tests
Tier: in-tree consensus verification. Owners: `crates/execution/src/chain/header_sync.rs` (`contextual_header_tests`: nBits, MTP, BIP94 timewarp, version floors), `crates/consensus/src/verify_block.rs` (BIP30 duplicate txids, BIP34 coinbase height, BIP68 locktimes, BIP141 commitments, weight limits). Third owner: `crates/execution/src/tests/persistence_tests.rs` (mutation failure boundaries, undo atomicity, BIP30 overwrite undo-coin removal).
```sh
cargo test --locked -p bitcoin-rs-execution header_sync::contextual_header_tests && cargo test --locked -p bitcoin-rs-consensus verify_block::tests
cargo test --locked -p bitcoin-rs-execution --lib persistence_tests
```
## 7. Daily fuzz targets and QA-assets corpus provenance
Tier: in-tree fuzzing and corpus regression. Contract: [qa-corpus](contracts/qa-corpus.md) (`QAC-01`..`QAC-05`). Provenance: [fuzz/CORPUS_PROVENANCE.md](../fuzz/CORPUS_PROVENANCE.md). bitcoinfuzz-module integration ([bitcoinfuzz/bitcoinfuzz#662](https://github.com/bitcoinfuzz/bitcoinfuzz/issues/662)) is in progress, not completed verification. Prerequisites: `jq`, `sha1sum`, `cargo-fuzz`, nightly Rust + `llvm-tools-preview`; writable companion corpus checkout on the same filesystem. Owners: `scripts/import-qa-assets.sh`, `scripts/import-reference-corpora.sh`, `scripts/validate-corpus-seeds.sh` (filesystem only: non-symlink regular files named by own SHA-1, no larger than `FUZZ_MAX_SEED_BYTES`, positive count, modes `0644`; no codec/verdict check; nonzero on first refusal). Additional owners: `scripts/run-fuzz-campaign.sh`, `crates/consensus/tests/primitives_differential.rs` (`QAC-05`: every seed vs pinned verdicts `accepted` byte-identical / `rejected:<kind>`; absent corpus skips loudly, absent `verdicts.json` degrades to shape check). Seeds from `rust-bitcoin/qa-assets`, `bitcoin/bitcoin`, `btcsuite/btcd` feed `p2p_message`, `block_validate`, `tx_validate`, `script_eval`, `utxo_snapshot`.
```sh
# Native codec roundtrip check over corpus seeds:
BITCOIN_RS_FUZZ_CORPUS=../bitcoin-rs-fuzz-corpus/corpus cargo test --locked -p bitcoin-rs-consensus --test suite differential::
# Run a bounded fuzz campaign with target, seconds, corpus, and output paths:
./scripts/run-fuzz-campaign.sh p2p_message 60 ../bitcoin-rs-fuzz-corpus/corpus/p2p_message target/fuzz-campaign/p2p_message
```
## 8. Chainstate crash recovery and reorg evidence
Tier: in-tree durability and recovery verification. Contract: [recovery](contracts/recovery.md). Owners: `crates/execution/src/tests/recovery_marker_order_tests.rs`, `crates/execution/src/durable/tests.rs`, `crates/execution/src/assumeutxo/tests/recovery.rs` (SIGKILL mid-import/mid-activation/mid-validation; failure-receipt retention, durable-head checkpoint recovery, below-base reorgs; Core v2 fixture provenance `crates/storage/tests/fixtures/core-v2/README.md`; offline CLI [tools/snapshot/README.md](../tools/snapshot/README.md)). Additional owners: `crates/storage/tests/durable_head_store.rs`, `crates/storage/src/checkpoint/tests.rs`, `e2e/tests/reorg.rs`, `e2e/tests/reorg_state.rs`. AssumeUTXO recovery module runs against RocksDB. Host prerequisite: `e2e/tests/assumeutxo.rs::invalid_core_snapshots_fail_without_activating` needs byte-capable `/tmp`. It owns `core-\xff.dat` under `/tmp`, symlinks UTF-8 `core200.dat` in datadir, copies instead of cross-filesystem rename, and cleans up. The former `EILSEQ` (92) failure was not JSON serialization. Node datadir and global `TMPDIR` stay on configured disk-backed filesystems. Record an incapable lane as `BLOCKED`.
```sh
cargo test --locked -p bitcoin-rs-execution --lib recovery_marker_order_tests && cargo test --locked -p bitcoin-rs-execution --lib durable::tests
cargo test --locked -p bitcoin-rs-execution --lib assumeutxo::tests::recovery && cargo test --locked -p bitcoin-rs-storage --test suite durable_head_store::
cargo test --locked -p bitcoin-rs-e2e --test suite reorg::
```
## 9. External ecosystem compatibility matrix
Tier: strategic compatibility tracking. Contract/matrix: [ecosystem-compatibility](contracts/ecosystem-compatibility.md) (`ECO-08`), [api/ecosystem-compat.toml](api/ecosystem-compat.toml). Status: externally verified for P2P v1, BIP152, BIP157/158 (runner [tools/compact-filter-interop/README.md](../tools/compact-filter-interop/README.md)), and BIP324 v2. Partially compatible: peer lifecycle/address management, with deviations in P2P policy. Implemented: JSON-RPC, REST, ZMQ, Esplora API (Compose example [tools/btc-mempool-explorer/README.md](../tools/btc-mempool-explorer/README.md)), GetBlockTemplate, block submission, and USDT tracepoints. Experimental: BIP352 Silent Payments (`getblocktweaks`, [silent-payments](silent-payments.md)), the regtest-only Stratum V2 adapter (no production qualification; [tools/stratum-sv2/README.md](../tools/stratum-sv2/README.md)), and the standalone LDK L1 adapter ([tools/ldk/README.md](../tools/ldk/README.md)). Intentionally unsupported: Core IPC adapters. Lightning is evidence-gated, not a lane verdict. LND `v0.21.4-beta` shows five cells `not exercised`. Only record `parent-live-4` is unretained gitignored scratch: 61-dirty source, `.outline` runner copy diverging from the tracked script, unverified manifest signature, no fresh Core comparison ([lightning-interop-matrix](lightning-interop-matrix.md) section 2 through 3.1). CLN `v26.06.9` startup `failed` in retained qualified `run-2` (`.outline/evidence/lightning-live-cln/run-2/evidence.json`). The version gate refused `1400` below `220000`, while Core 31.1 reached `getinfo` ready. The other 4 cells are `not exercised` on causal startup, and `getblockfrompeer` reported `rs=method_not_found`/`core=rpc_error` (fallback only). Source HEAD `aab50bd64` with 7 dirty entries and 758 inputs (`stale_allowed:false`), node `48129ac5`, runner frozen `86eba76` with parent job `bg_543` checksum chain and exit `0` in `.outline/evidence/lightning-live-cln/run-2/verification.json`.
```sh
# Inspect rows and status vocabulary
cat docs/api/ecosystem-compat.toml
# CLN live cell with pinned artifacts; see docs/lightning-interop-matrix.md section 4 for the exact command
timeout --signal=TERM --kill-after=30 900 bash scripts/verify-lightning-interop.sh --target cln --bitcoin-rs-bin <path-to-built-bitcoin-rs> --bitcoind-bin <path-to-bitcoin-core-31.1> --cln-bin <extract-dir>/usr/bin/lightningd --cln-release-archive <dir>/clightning-v26.06.9-Ubuntu-26.04-amd64.tar.xz --cln-library-path <dir>/libpq-probe/root/usr/lib/x86_64-linux-gnu
```
## 10. USDT / bpftrace observability validation
Tier: in-tree probe ABI inspection; live tracing planned. Docs: [tracing](tracing.md). Owners: `crates/consensus/probes.d`, `crates/consensus/tests/sdt_notes.rs`, `docs/tracing/smoke.bt` (from Core `contrib/tracing`). Verifies static USDT probe notes (`net`, `validation`, `mempool`) match Core probe ABI; live `bpftrace`/BCC tracing remains planned.
```sh
# Verify enabled probe SDT notes in the test binary (or set SDT_ELF=$PWD/target/release/bitcoin-rs):
cargo test --locked -p bitcoin-rs-consensus --features usdt --test sdt_notes
# Separately verify that a feature-off build contains no probe notes:
cargo test --locked -p bitcoin-rs-consensus --no-default-features --test sdt_notes
```
## 11. Core functional suite against the node binary
Tier: in-tree harness. Contract: [core-differential](contracts/core-differential.md) (`CORE-07`). Owners: `tools/core-functional/` (extraction `fetch-core-tests.sh`, runner `run.sh` + `tools/core-functional/bin/runner.py`, adapter `bin/bitcoind-wrapper`, client shims `shim/sitecustomize.py`); measured record [tools/core-functional/README.md](../tools/core-functional/README.md). Runs Bitcoin Core v31.1's `test/functional` suite, extracted from a local checkout at a verified tag with a `PROVENANCE` stamp (no Core code is vendored or modified), against a built bitcoin-rs binary through an argv/conf/cookie adapter with disclosed client shims (the RPC no-op and stop-wait patches carry disable env vars; the MiniWallet patch is unconditional). Status: measured campaign baseline. Runs 1-5b, one published execution per candidate (run 4's discarded first attempt on a stray-slash subversion binary and run 5's isolated same-binary rerun of `rpc_validateaddress` after a host port collision are disclosed in the record), 8/46 pass with every failure triaged to a numbered node gap (gap ledger NG-1..NG-20, issue #1757). No claim extrapolates beyond the selected candidates. Host prerequisite: a local Core checkout; CI does not run the lane.
```sh
python3 tools/core-functional/tests/wrapper_smoke.py
```
