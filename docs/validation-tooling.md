# Validation tooling and evidence index
Operator entry point to the validation, verification, and differential evidence lanes. Each lane is owned by its scripts, crates, suites, and contracts; this index adds no runner, framework, or test-only state.
## Evidence tier distinction
Per [ecosystem-compatibility](contracts/ecosystem-compatibility.md) (`ECO-02`, `ECO-08`, `ECO-09`): **externally verified** = unmodified external program exercises `bitcoin-rs` via public P2P/RPC/REST/ZMQ/CLI; **implemented / tested** = in-tree reference vectors, differentials, oracles, fuzz, and fault-injection suites.
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
| [Offline comparator](#9-offline-full-validation-comparator) | Harness tested; campaign pending |
| [Ecosystem compatibility](#10-external-ecosystem-compatibility-matrix) | Per-surface evidence |
| [USDT observability](#11-usdt--bpftrace-observability-validation) | ABI tested; live tracing planned |
| [Measured campaign runner & analyzer](#12-measured-campaign-runner-and-analyzer) | Harness tested; campaign pending |
## 1. Live Bitcoin Core P2P and chain-identity differential
Tier: externally verified. Contract: [core-differential](contracts/core-differential.md) (`CORE-01`, `CORE-02`, `CORE-03`, `CORE-05`, `CORE-06`). Owners: `scripts/install-bitcoind.sh` (`scripts/install-bitcoind.ps1` on Windows), `scripts/run-p2p-core-interop.sh`, `crates/p2p/tests/core_interop_live.rs`. Fixtures: BIP324 vectors `crates/p2p/tests/data/bip324/README.md`; AddrMan/ASMap `crates/p2p/tests/support/README.md`, `crates/p2p/tests/data/asmap-core-v31.1.README.md`, `crates/p2p/tests/data/asmap-linked-ipv4-core-v31.1.README.md`, `crates/p2p/tests/data/addrman-canonical-v1-shared.json`; no historical-schema migration fixtures; pre-release AddrMan freeze: [p2p-compatibility](policies/p2p-compatibility.md) section 7. Verifies pinned Core 31.1 (SHA-256 in `crates/rpc/core-compat.toml`) regtest handshake/IBD/BIP152 A-C/tip agreement (`getblockcount`, `getbestblockhash`, `getblockchaininfo.{chain,blocks}`), direct `inv`/`headers`/`cmpctblock` wire comparison across a reorg, bidirectional BIP324 v2 (main node stays v1) with Core ping replies. Compact-block relay counts are diagnostic per `ECO-09`.
```sh
scripts/install-bitcoind.sh --print-path && cargo build --locked -p bitcoin-rs --profile quickstart --no-default-features --features fjall,zmq
scripts/run-p2p-core-interop.sh --bitcoind-command "$(scripts/install-bitcoind.sh --print-path)" --bitcoin-rs-command target/quickstart/bitcoin-rs --workdir target/core-differential/run --evidence target/core-differential/evidence.json
P2P_CORE_INTEROP_EVIDENCE=target/core-differential/evidence.json cargo test --locked -p bitcoin-rs-p2p --test core_interop_live -- --ignored
```
Artifacts: CI retains `target/core-differential/*.log`, `evidence.json` in `core-differential-<run_attempt>` for 7 days.
## 2. Live Core block and transaction acceptance differential
Tier: in-tree live-reference differential (in-repo `ProcessNode` drives both public RPCs; unmodified pinned Core is the behavioral oracle), not external-consumer verification. Contract: [core-differential](contracts/core-differential.md) (`CORE-04`). Owners: `e2e/tests/acceptance.rs`, `e2e::differential`, `ProcessNode`. Verifies identical accept/reject on regtest for coinbase-only blocks, bad merkle roots, multiple coinbases, short scriptSig, excessive values, BIP34 height mismatches, MTP boundaries, mature/immature spends, duplicate inputs, overspends, relative locktimes (`submitblock`, `testmempoolaccept`). Broader fuzzing/rule coverage is not implemented.
```sh
scripts/install-bitcoind.sh --print-path && cargo build --locked --release -p bitcoin-rs
BITCOIN_RS_NODE="$PWD/target/release/bitcoin-rs" BITCOIN_RS_REFERENCE_BITCOIND="$(scripts/install-bitcoind.sh --print-path)" cargo test --locked -p bitcoin-rs-e2e --test acceptance
```
Artifacts: `acceptance-*.json` under the test process evidence directory.
## 3. Bitcoin Core script and transaction vectors
Tier: in-tree reference vector evidence. Owners: `crates/script/tests/core_vectors.rs` (`script_tests.json`, `tx_valid.json`, `tx_invalid.json` script-verification columns; runnable rows pinned as executed/skipped/mismatch; tx columns check script verification only, `BADTX` non-script rows skipped), `crates/consensus/tests/vectors.rs` (vector loading/deserialization, script flag parsing, legacy sighash; no accept/reject comparison against expected validity).
```sh
cargo test --locked -p bitcoin-rs-script --test core_vectors && cargo test --locked -p bitcoin-rs-consensus --test vectors
```
## 4. Native sighash checks against independent implementation
Tier: in-tree differential evidence. Owners: `crates/consensus/tests/shared_sighash.rs` (native vs `rust-bitcoin` `sighash::SighashCache`), `crates/script/tests/proptest.rs` (`rust-bitcoin` sighash/Schnorr oracle), `crates/primitives/tests/differential.rs` (`sighash.json` legacy vectors), `crates/primitives/tests/bip_vectors.rs` (BIP143/BIP341; provenance `crates/primitives/tests/vectors/PROVENANCE.md`). Verifies exact digest equality for `SIGHASH_ALL/NONE/SINGLE/ANYONECANPAY/DEFAULT` across legacy, BIP143, BIP341.
```sh
cargo test --locked -p bitcoin-rs-consensus --test shared_sighash && cargo test --locked -p bitcoin-rs-script --test proptest
cargo test --locked -p bitcoin-rs-primitives --test differential && cargo test --locked -p bitcoin-rs-primitives --test bip_vectors
```
## 5. libbitcoinkernel oracle and scoped native parity
Tier: in-tree oracle and differential evidence. Related: [validation-default](contracts/validation-default.md) (`Proven by` evidence; no `VAL-02` clause). Owners: `crates/consensus/tests/kernel_vector_parity.rs` (Core vectors via `verify_tx_scripts`; `BADTX` excluded; kernel-vs-vector oracle, not native-vs-kernel over the full corpus), `crates/consensus/tests/kernel_block_parity.rs` (kernel vs native accept/reject on six mainnet fixtures `legacy_p2pk/p2pkh`, `p2sh_spend`, `segwit_v0_spend`, `taproot_keypath/scriptpath_spend`, all `interpreter_parity: true`, plus Taproot script-path non-vacuity; provenance `crates/consensus/tests/vectors/scripts/README.md`). Prerequisites: `libboost-dev`, `cmake`, C++ toolchain.
```sh
cargo test --locked -p bitcoin-rs-consensus --features kernel --test kernel_vector_parity --test kernel_block_parity -- --nocapture
```
## 6. Contextual consensus-rule tests
Tier: in-tree consensus verification. Owners: `crates/chain/src/header_sync.rs` (`contextual_header_tests`: nBits, MTP, BIP94 timewarp, version floors), `crates/consensus/src/verify_block.rs` (BIP30 duplicate txids, BIP34 coinbase height, BIP68 locktimes, BIP141 commitments, weight limits), `crates/chainstate/tests/unit/apply/persistence_tests.rs` (mutation failure boundaries, undo atomicity, BIP30 overwrite undo-coin restoration).
```sh
cargo test --locked -p bitcoin-rs-chain header_sync::contextual_header_tests && cargo test --locked -p bitcoin-rs-consensus verify_block::tests
cargo test --locked -p bitcoin-rs-chainstate --lib persistence_tests
```
## 7. Daily fuzz targets and QA-assets corpus provenance
Tier: in-tree fuzzing and corpus regression. Contract: [qa-corpus](contracts/qa-corpus.md) (`QAC-01`..`QAC-05`). Provenance: [fuzz/CORPUS_PROVENANCE.md](../fuzz/CORPUS_PROVENANCE.md). bitcoinfuzz-module integration ([bitcoinfuzz/bitcoinfuzz#662](https://github.com/bitcoinfuzz/bitcoinfuzz/issues/662)) is in progress, not completed verification. Prerequisites: `jq`, `sha1sum`, `cargo-fuzz`, nightly Rust + `llvm-tools-preview`; writable companion corpus checkout on the same filesystem. Owners: `scripts/import-qa-assets.sh`, `scripts/import-reference-corpora.sh`, `scripts/validate-corpus-seeds.sh` (filesystem only: non-symlink regular files named by own SHA-1, no larger than `FUZZ_MAX_SEED_BYTES`, positive count, modes `0644`; no codec/verdict check; nonzero on first refusal), `scripts/run-fuzz-campaign.sh`, `crates/primitives/tests/differential.rs` (`QAC-05`: every seed vs pinned verdicts `accepted` byte-identical / `rejected:<kind>`; absent corpus skips loudly, absent `verdicts.json` degrades to shape check). Seeds from `rust-bitcoin/qa-assets`, `bitcoin/bitcoin`, `btcsuite/btcd` feed `p2p_message`, `block_validate`, `tx_validate`, `script_eval`, `utxo_snapshot`.
```sh
# Native codec roundtrip check over corpus seeds:
BITCOIN_RS_FUZZ_CORPUS=../bitcoin-rs-fuzz-corpus/corpus cargo test --locked -p bitcoin-rs-primitives --test differential
# Run a bounded fuzz campaign with target, seconds, corpus, and output paths:
./scripts/run-fuzz-campaign.sh p2p_message 60 ../bitcoin-rs-fuzz-corpus/corpus/p2p_message target/fuzz-campaign/p2p_message
```
## 8. Chainstate crash recovery and reorg evidence
Tier: in-tree durability and recovery verification. Contract: [recovery](contracts/recovery.md). Owners: `crates/chainstate/tests/unit/recovery_marker_order_tests.rs`, `crates/chainstate/tests/unit/durable_replay_tests.rs`, `crates/chainstate/tests/unit/assumeutxo_recovery_tests.rs` (SIGKILL mid-import/mid-activation/mid-validation; failure-receipt retention, durable-head checkpoint recovery, below-base reorgs; Core v2 fixture provenance `crates/utxo/tests/fixtures/core-v2/README.md`; offline CLI [tools/snapshot/README.md](../tools/snapshot/README.md)), `crates/storage/tests/durable_head_store.rs`, `crates/storage/src/checkpoint/tests.rs`, `e2e/tests/reorg.rs`, `e2e/tests/reorg_state.rs` (mapping [e2e/REORG-COVERAGE.md](../e2e/REORG-COVERAGE.md)). AssumeUTXO recovery module requires `fjall`. Host prerequisite: `e2e/tests/assumeutxo.rs::invalid_core_snapshots_fail_without_activating` needs byte-capable `/tmp` (owns `core-\xff.dat` under `/tmp`, symlinks UTF-8 `core200.dat` in datadir, copies instead of cross-filesystem rename, cleans up; former `EILSEQ` (92) failure was not JSON serialization). Node datadir and global `TMPDIR` stay on configured disk-backed filesystems. Record an incapable lane as `BLOCKED`.
```sh
cargo test --locked -p bitcoin-rs-chainstate --lib recovery_marker_order_tests && cargo test --locked -p bitcoin-rs-chainstate --lib durable::tests
cargo test --locked -p bitcoin-rs-chainstate --features fjall --lib assumeutxo::tests::recovery && cargo test --locked -p bitcoin-rs-storage --test durable_head_store
cargo test --locked -p bitcoin-rs-e2e --test reorg
```
## 9. Offline full-validation comparator
Tier: in-tree benchmark / parity harness. Contracts: [offline-full-validation](benchmarks/offline-full-validation.md), [campaign-corpora](contracts/campaign-corpora.md) (`CORP-01`..`CORP-05`). Owners: `tools/benchmark-campaign/offline_full_validation.py`, `tools/benchmark-campaign/test_offline_full_validation.py`, `tools/campaign-corpus/corpus.py` (`export` pulls the frozen archive from a Core REST interface, `verify` rebinds an archive to its manifest). Runs SHA-256-pinned `core.binary`/`candidate.binary` from `offline-full-validation-config-v1` on the same hash-pinned Core-framed archive (`blk*.dat`); each arm runs its verified copy at `<root>/<NN>-<role>/node-under-test` (`{binary}` placeholder); for a Core 31.1 arm point `core.binary` at `scripts/install-bitcoind.sh --print-path` output (default `${HOME}/bitcoin-core-31.1/bin/bitcoind` unless `BITCOIND_PREFIX` set); harness performs no Core version check. Asserts identical certified end state (height, best hash, UTXO count, total amount, `MuHash3072`, `hash_serialized_3`) plus timing. Unit tests prove custody/validation/percentiles in CI; live C150/Cmodern full-mainnet execution is planned, not executed.
```sh
python3 tools/benchmark-campaign/test_offline_full_validation.py && python3 tools/campaign-corpus/test_corpus.py
# Export the frozen input archive from a Core node REST interface (fetches /rest/blockhashbyheight/<height>.hex and /rest/block/<hash>.bin):
python3 tools/campaign-corpus/corpus.py export --rest-url <host:port> --corpus-id C150 --archive <archive-path> --manifest <manifest-path>
```
## 10. External ecosystem compatibility matrix
Tier: strategic compatibility tracking. Contract/matrix: [ecosystem-compatibility](contracts/ecosystem-compatibility.md) (`ECO-08`), [api/ecosystem-compat.toml](api/ecosystem-compat.toml). Status: externally verified: P2P v1, BIP152, BIP157/158 (runner [tools/compact-filter-interop/README.md](../tools/compact-filter-interop/README.md)), BIP324 v2; partially compatible: peer lifecycle/address management (deviations in P2P policy); implemented: JSON-RPC, REST, ZMQ, Esplora API (Compose example [tools/btc-mempool-explorer/README.md](../tools/btc-mempool-explorer/README.md)), GetBlockTemplate, block submission, USDT tracepoints; experimental: BIP352 Silent Payments (`getblocktweaks`, [silent-payments](silent-payments.md)), regtest-only Stratum V2 adapter (no production qualification; [tools/stratum-sv2/README.md](../tools/stratum-sv2/README.md)), standalone LDK L1 adapter ([tools/ldk/README.md](../tools/ldk/README.md)); intentionally unsupported: Core IPC adapters. Lightning is evidence-gated, not a lane verdict: LND `v0.21.4-beta` five cells `not exercised` (only record `parent-live-4` is unretained gitignored scratch: 61-dirty source, `.outline` runner copy diverging from the tracked script, unverified manifest signature, no fresh Core comparison; [lightning-interop-matrix](lightning-interop-matrix.md) section 2 through 3.1); CLN `v26.06.9` startup `failed` in retained qualified `run-2` (`.outline/evidence/lightning-live-cln/run-2/evidence.json`): version-gate refusal `1400` below `220000` with Core 31.1 reaching `getinfo` ready, other 4 cells `not exercised` on causal startup, `getblockfrompeer` `rs=method_not_found`/`core=rpc_error` (fallback only), source HEAD `aab50bd64` with 7 dirty entries and 758 inputs (`stale_allowed:false`), node `48129ac5`, runner frozen `86eba76` with parent job `bg_543` checksum chain and exit `0` in `.outline/evidence/lightning-live-cln/run-2/verification.json`.
```sh
# Inspect rows and status vocabulary
cat docs/api/ecosystem-compat.toml
# CLN live cell with pinned artifacts; see docs/lightning-interop-matrix.md section 4 for the exact command
timeout --signal=TERM --kill-after=30 900 bash scripts/verify-lightning-interop.sh --target cln --bitcoin-rs-bin <path-to-built-bitcoin-rs> --bitcoind-bin <path-to-bitcoin-core-31.1> --cln-bin <extract-dir>/usr/bin/lightningd --cln-release-archive <dir>/clightning-v26.06.9-Ubuntu-26.04-amd64.tar.xz --cln-library-path <dir>/libpq-probe/root/usr/lib/x86_64-linux-gnu
```
## 11. USDT / bpftrace observability validation
Tier: in-tree probe ABI inspection; live tracing planned. Docs: [tracing](tracing.md). Owners: `crates/consensus/probes.d`, `crates/consensus/tests/sdt_notes.rs`, `docs/tracing/smoke.bt` (from Core `contrib/tracing`). Verifies static USDT probe notes (`net`, `validation`, `mempool`) match Core probe ABI; live `bpftrace`/BCC tracing remains planned.
```sh
# Verify enabled probe SDT notes in the test binary (or set SDT_ELF=$PWD/target/release/bitcoin-rs):
cargo test --locked -p bitcoin-rs-consensus --features usdt --test sdt_notes
# Separately verify that a feature-off build contains no probe notes:
cargo test --locked -p bitcoin-rs-consensus --no-default-features --test sdt_notes
```
## 12. Measured campaign runner and analyzer
Tier: in-tree benchmark campaign harness. Contracts: [measured-campaign](benchmarks/measured-campaign.md), [benchmarks/README](benchmarks/README.md), [hot-path-attribution](contracts/hot-path-attribution.md) (`HPA-10`, `HPA-13`). Owners: `tools/benchmark-campaign/measured_runner.py`, `tools/benchmark-campaign/test_measured_campaign.py`, analyzer `tools/benchmark-campaign/measured_analyze.py`, shared sampler `tools/benchmark-support/measured_samples.rs`. Validates registration JSON, five-tree digests, build receipts, baseline evidence, `/proc/cpuinfo` affinity/model bindings pre-launch (`validate`, `plan`, `run`); parses Criterion `sample.json`, `MRP_COUNTED_SAMPLE` lines, T2/T3 node JSONL into `INCONCLUSIVE`/`REGRESSION`/`NON_REGRESSION_EVIDENCED`/`AT_FLOOR`. The offline synthetic probe verifies schema/parser/self-binding/adversaries on stub fixtures; passing it is not a campaign or acceptance.
`uv run --offline --no-project --script tools/benchmark-campaign/test_measured_campaign.py`
## 12a. Filesystem-aware Linux measurement boundary
Tier: in-tree benchmark campaign harness (diagnostic, not product-cell qualification). Owner: `tools/benchmark-campaign/filesystem.py` (one owner for mount/filesystem/backing-counter scope plus read-only cumulative samples; stdlib only), tests `tools/benchmark-campaign/test_filesystem.py`; the private index-write-attribution harness delegates mountinfo/sysfs/diskstats lookup to it and keeps its own gate. One target filesystem per run; apparent bytes, allocated bytes, per-process I/O, host block-device writes reported separately, never merged. Scopes: `regular_block_device` (available), `zfs_pool`/`composite_anonymous` (overlay/tmpfs/ramfs/network/fuse/9p/virtiofs/major-0)/`ambiguous_multi_device` (btrfs/stacked; counters listed, never summed)/`unavailable` (no mount, missing/unparsable counter, wrap/reset, wrong `--device` override): all unavailable reported with reason, never zero. Read-only mechanisms: `/proc/self/mountinfo` (octal-escape, longest-prefix), `/sys/dev/block/<MAJ:MIN>/stat` sectors-written (512-byte units), `/proc/diskstats` sectors as diagnostic, `slaves`/`holders` topology; one device counter per scope, never parent disk added. Counter is host-wide, never attests isolation; wrap/reset yields unavailable. Per-filesystem physical writes are never fabricated from allocation counters, per-process I/O counters, or pool totals.
```sh
python3 tools/benchmark-campaign/filesystem.py identify --path /srv/scratch
python3 tools/benchmark-campaign/filesystem.py sample --path /srv/scratch
```
