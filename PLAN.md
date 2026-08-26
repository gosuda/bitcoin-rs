# bitcoin-rs Implementation Plan

> **Execution:** Steps use checkbox (`- [ ]`) syntax. Every task in this plan must ship before bitcoin-rs is declared done.
> **Historical plan.** This document preserves the original implementation roadmap,
> including its now-removed Electrum design. The current architecture and supported
> configuration are defined by `CONCEPTS.md` and `docs/getting-started.md`; do not
> treat unfinished tasks or dependency entries below as current work.
> Compact filters (issue #143) and the experimental Utreexo node mode
> (issue #144) are removed roadmap items; their historical task and gate text
> below does not describe supported code or configuration.

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement task-by-task. Steps use checkbox (`- [ ]`) syntax. **Do not split phases or roadmaps** — every task in this plan must ship before bitcoin-rs is declared done.

**Goal:** Ship `bitcoin-rs` — a single-binary fast Bitcoin full node in Rust 2024. Natively-integrated UTXO (gocoin shape), Electrum-style index (electrs shape), utreexo accumulator (utreexod shape), in-process wallet (PSBT builder; **no private keys, no signing**), in-process mining (getblocktemplate), pruning, coinstats index, four pluggable storage backends (RocksDB / MDBX / fjall / redb), SIMD JSON on the RPC hot path. All production polish (graceful shutdown, ban-score, crash recovery, metrics, structured logging, config) is part of core scope. BIP157/158 compact filters were specced and then removed (issue #143): no in-tree consumer existed and the P2P serving half was never implemented.

**Architecture:** One process. One `crossbeam-channel`-driven event loop (no tokio/async-std). UTXO held as 256 shards of `hashbrown::HashTable<ArenaRef<'arena>>` over `bumpalo::Bump`, arenas pinned via `self_cell!` so the lifetime is sound (not transmuted), each shard guarded by `parking_lot::RwLock` and `CachePadded` against false sharing. Block tree as `slab::Slab<Node>` + `u32 NodeId`; tip published via `arc_swap::ArcSwapOption<TipSnapshot>`; chainwork as `ruint::Uint<256,4>`. Consensus *borrowed* from `bitcoinkernel >=0.2, <0.3` (default-on, alpha-but-load-bearing) — our Rust validator runs in parallel and is asserted byte-identical to kernel for every accepted block. Wallet is in-process PSBT builder + descriptor watcher with **zero private-key surface**: external signers receive a PSBT, return a signed PSBT, finalize happens inside the daemon. Storage is a `KvStore` trait with **fjall as the launch default**; RocksDB, `signet-libmdbx` (MDBX — memory-mapped CoW B+tree), and `redb` (pure-Rust B+tree) live behind cargo features. All four backends are gated by G7 backend-equivalence.

**Tech stack:** Rust 2024 edition, MSRV 1.95.0, resolver `"3"`. `mimalloc` global allocator; allocator and non-UTXO hasher alternates require fresh G14 evidence before promotion. See the full Dependency Table below for the vetted floor list; every entry was audited against crates.io / GitHub on 2026-05-19 and pins to the latest stable line. The audit summary lives in [docs/plans/2026-05-19-ultrareview-log.md](docs/plans/2026-05-19-ultrareview-log.md).

---

## Design Principles

1. **KISS first.** Reach for the simplest data structure that fits the access pattern. Complexity is paid for by benchmarks, not aesthetics.
2. **Minimal allocations on hot paths.** Block validation, UTXO commit, header sync, p2p inbound — none of these may allocate per item. Arenas, slabs, `tinyvec`, `smallvec`, `compact_str` cover the common cases.
3. **Zero-copy where the wire allows.** Inbound p2p frames, on-disk records, snapshot files all use `zerocopy` / `bytemuck` over `Vec<u8>::copy_from_slice` when the layout is fixed.
4. **Hot path stack-allocated.** Validation / script verify / merkle / UTXO lookup use `[u8; N]`, `MaybeUninit`, `tinyvec::ArrayVec` for bounded fan-out.
5. **Zig-style scratch arenas.** Thread-local `bumpalo::Bump`, `Bump::reset()` on block boundary (no `Drop` calls). Per-shard arenas live until shutdown and are pinned via `self_cell!`.
6. **Pre-allocate.** Any `Vec`/`HashMap` whose final size is knowable uses `with_capacity` + `push_within_capacity`.
7. **Unsafe when it pays its way.** `unsafe` is permitted wherever a bench shows a genuine win. Every `unsafe` block carries a `// SAFETY:` rationale (enforced via `clippy::undocumented_unsafe_blocks = deny`) and a one-line bench delta in the commit body (`Δp95: NNμs → MMμs`). Prefer `zerocopy` / `NonNull<T>` / `bumpalo` shapes when they match the win; reach for raw `unsafe` when they don't.
8. **Data structures.** UTXO map: `hashbrown::HashTable` over `Box<bumpalo::Bump>` pinned via `self_cell!`. Block tree: `slab::Slab<Node>` + `u32 NodeId`. Chainwork compare: `ruint::Uint<256, 4>`. Mempool by-fee: gocoin's Pareto-front priority queue on `tinyvec::ArrayVec`. Mempool funding/spending: `BTreeSet` (Electrum needs prefix range scans). SHA-256 follows the current manifest: `sha2 >=0.11, <0.12` and `bitcoin_hashes >=0.14.100, <0.15`; any SHA acceleration change requires fresh G14 evidence against that dependency graph. Non-UTXO hashing: `foldhash` default; `gxhash` opt-in behind an `x86_64-aes` runtime check; `nohash-hasher` for UTXO key (8-byte TXID prefix is already uniform).
9. **Consensus is borrowed, not invented.** `bitcoinkernel >=0.2, <0.3` is the consensus authority. Our Rust validator runs in parallel and must be byte-identical for every accepted block. If kernel and our Rust path disagree, kernel wins and our Rust path is the bug. A `pure-rust-validation` feature is deferred until 12 months of unbroken mainnet kernel parity.
10. **Wallet has no private-key surface.** The wallet crate builds PSBTs, watches descriptors, selects coins, bumps fees, finalizes signed PSBTs. It never reads, stores, or accepts a private key. External signers (HWI, MPC service, hardware wallet, air-gapped device) sign PSBTs and hand them back. The signing trait is a `Fn(&Psbt) -> Psbt` — implementation lives outside the daemon.

---

## Workspace Layout

```
bitcoin-rs/
├── Cargo.toml                    # workspace; resolver "3"; members + lints
├── Cargo.lock                    # committed
├── rust-toolchain.toml           # channel = "1.95.0"
├── clippy.toml                   # MSRV + cognitive-complexity + pedantic deny list
├── PLAN.md                       # mirror of this plan (Task 0 creates)
├── README.md
├── CONCEPTS.md                   # project vocabulary
├── DEVIATIONS.md                 # dependency-deviation ledger
├── LICENSE                       # MIT/Apache-2.0 dual
├── deny.toml                     # cargo-deny config
├── .github/workflows/ci.yml      # fmt + clippy -D warnings + test + bench-smoke + deny
├── docs/                         # benchmarks, solutions, plans, policies, getting-started, REST
├── tools/                        # benchmark-campaign, bip300301-enforcer, checksig-census
├── scripts/                      # G2/G14 evidence-collection and measurement drivers
├── fuzz/                         # cargo-fuzz targets (utxo_snapshot, block/tx decode, p2p, script)
├── crates/
│   ├── primitives/               # Hash256, OutPoint, Tx, Block, Header, varint, network, sighash types
│   ├── consensus/                # kernel-authoritative validator + parallel Rust path
│   │   └── benches/              # verify_tx.rs, merkle.rs
│   ├── script/                   # interpreter (legacy/segwit/taproot/sighash variants/sigops)
│   ├── storage/                  # KvStore trait + fjall default + rocksdb + mdbx + redb feature impls
│   │   └── benches/              # kvstore_backends.rs — rocksdb vs mdbx vs fjall vs redb
│   ├── utxo/                     # 256-shard HashTable + Bump + self_cell + RwLock; commit/get/undo/defrag/snapshot
│   │   └── benches/              # utxo_commit.rs
│   ├── utreexo/                  # rustreexo Pollard/Stump/MemForest; proof attach/verify; bridge-node
│   ├── chain/                    # Slab<BlockTreeNode>+u32 NodeId; ArcSwapOption tip; ruint chainwork; reorg
│   ├── index/                    # port electrs verbatim (embedded; 5 CFs; HashPrefixRow; bitcoin_slices visitor)
│   │   └── benches/              # history_resolve.rs
│   ├── pruning/                  # block-file + undo-file pruner; utreexo-only mode coordinator
│   ├── mempool/                  # Pareto-front by-fee; RBF (BIP125); package eviction; ancestor/descendant limits
│   ├── p2p/                      # peer FSM; addrv2; wtxid relay (BIP339); ban-score; compact-block-relay (BIP152) opt
│   ├── wallet/                   # descriptors (BIP380/381/382); PSBT v2 builder (BIP370); coin selection via bdk_coin_select; fee bump (RBF); NO signing
│   ├── mining/                   # getblocktemplate (BIP22/23); mining policy from mempool; coinbase template
│   ├── rpc/                      # Bitcoin-Core-compat JSON-RPC subset
│   ├── electrum/                 # Electrum protocol over the index
│   │   └── benches/              # electrum_methods.rs
│   ├── node/                     # event loop; config (TOML + bitcoin.conf compat + CLI + env); signal handling; metrics; tracing; graceful shutdown
│   │   └── benches/              # sync_pipeline.rs, sync_apply_metrics.rs
└── bin/
    └── bitcoin-rs/               # main.rs; thin — wires `crates/node`; tests/gates/g01..g15
```

Each crate's `Cargo.toml` inherits `package.rust-version`, `package.edition`, and lints from `workspace`. No crate ships its own `[lints]` block.

---

## Tech-Stack Dependency Table

Stored once in `bitcoin-rs/Cargo.toml` under `[workspace.dependencies]`. Per-crate `Cargo.toml` files re-declare with `<dep>.workspace = true`.

| Dep | Floor | Features | Notes |
|---|---|---|---|
| `mimalloc` | `>=0.1.50` | `[]` | `#[global_allocator]` in `bin/bitcoin-rs`; latest 0.1.50 (2026-04) [purpleprotocol/mimalloc_rust](https://github.com/purpleprotocol/mimalloc_rust) |
| `bitcoinkernel` | `>=0.2, <0.3` | `[]` | default-on consensus authority; active manifest line. Plan accepts the alpha cost because parity gating is the load-bearing safety net. |
| `bitcoin` | `>=0.32, <0.33` | `["std", "secp-recovery", "serde"]` + the crate's rand feature (exact name in `Cargo.toml`) | encode/decode + types. Stay on stable 0.32.x; 0.33 is still `0.33.0-beta` as of 2026-05 — wait for final |
| `secp256k1` | `>=0.31` | `["std", "alloc", "recovery", "rand", "serde", "global-context"]` | latest stable 0.31.x; 0.32 is still beta. Batch Schnorr `verify_schnorr_batch` available in 0.31+ |
| `sha2` | `>=0.11, <0.12` | `[]` | active manifest line; 0.11 exposes no `std`/`asm` feature, so SHA acceleration changes require fresh G14 evidence |
| `bitcoin_hashes` | `>=0.14.100, <0.15` | `["std"]` | active manifest line aligned with `bitcoin 0.32`; 0.14 exposes no `asm` feature and 1.0 breaks the current bitcoin-io graph |
| `hashbrown` | `>=0.17.1, <0.18` | `["inline-more", "default-hasher", "allocator-api2"]` | `HashTable` API is the stable raw-insertion API (the old `raw-entry` API is deprecated); MSRV 1.95 matches; no `nightly` feature |
| `bumpalo` | `>=3.20` | `["collections"]` | per-shard + thread-local scratch arenas with `Bump::reset()` on block boundary |
| `self_cell` | `>=1.2.2` | `[]` | proc-macro-free; pins `Box<Bump>` address so `HashTable<&'arena T>` is sound across moves |
| `ruint` | `>=1.12` | `["alloc"]` | `Uint<256, 4>` for chainwork (constant-time compare beats heap-allocated bignums) |
| `slab` | `>=0.4` | `["serde"]` | `Slab<BlockTreeNode>` keyed by `u32 NodeId` |
| `arc-swap` | `>=1.9` | `[]` | tip snapshot RCU (crates.io name is hyphenated; the Rust path is `arc_swap::`); 1.9.1 latest |
| `parking_lot` | `>=0.12.5, <0.13` | `["arc_lock", "send_guard"]` | per-shard `RwLock` (0.12 line; 0.13 does not exist); the `disallowed-types` clippy rule below routes every accidental `std::sync::*` here |
| `crossbeam-channel` | `>=0.5.15` | `[]` | event loop `Select`; non-negotiable for the architecture |
| `crossbeam-utils` | `>=0.8` | `[]` | `CachePadded` against false sharing on shard array |
| `rayon` | `>=1.12` | `[]` | block-parallel script verify via `rayon::scope` |
| `foldhash` | `>=0.2` | `[]` | default hasher (non-UTXO); 0.2 latest; explicit `BuildHasher` everywhere |
| `gxhash` | `>=3.5, <4` | `["std", "hybrid"]` | opt-in `[features] gxhash = ["dep:gxhash"]` — runtime AES-NI probe + fallback to foldhash |
| `nohash-hasher` | `>=0.2` | `[]` | identity hasher for the UTXO key (8-byte TXID prefix is uniform-by-construction) |
| `rapidhash` | `>=4.1` | `[]` (dev-dep only) | candidate non-UTXO hasher for future G14 comparison; promoted only if a clean measured win materializes |
| `tinyvec` | `>=1.11` | `["alloc"]` | primary `ArrayVec` for hot paths (100 % safe, no unsafe); mempool Pareto entries, sighash cache slots |
| `smallvec` | `>=1.15` | `["union", "const_generics"]` | spill-tolerant cases only; `arrayvec` is rejected as effectively frozen |
| `compact_str` | `>=0.9` | `[]` | SSO string for Electrum method names + tag strings |
| `bytemuck` | `>=1.25` | `["derive"]` | `Pod` + `Zeroable` on fixed-layout wire types |
| `zerocopy` | `>=0.8` | `["derive"]` | 0.8 is a trait-rewrite vs 0.7 — `TryFromBytes`/`IntoBytes`/`FromBytes` + `KnownLayout`/`Immutable`/`Unaligned` markers. Use exclusively for snapshot records + zerocopy on-disk index rows |
| `lz4_flex` | `>=0.13, <0.14` | `["std", "frame"]` | pure-Rust LZ4 for snapshot + custom-format compression (rocksdb feature already pulls C zstd) |
| `rust-rocksdb` | `>=0.50, <0.51` | `["mt_static", "snappy", "lz4", "zstd"]` | storage feature `rocksdb`; zaidoon1 fork is the active maintained binding (0.50 line) |
| `signet-libmdbx` | `>=0.8` | `[]` | storage feature `mdbx` — init4tech/mdbx fork of reth-libmdbx; Reth + Erigon + Silkworm + Akula all use libmdbx in production. Memory-mapped CoW B+tree, wait-free readers, no WAL. **Strong candidate for default after G7 benchmarks**. License MIT/Apache-2.0 ([crates.io/signet-libmdbx](https://crates.io/crates/signet-libmdbx)) |
| `fjall` | `>=3.1.4, <4` | `["lz4"]` | storage **default** — pure-Rust LSM with multi-keyspace (column families), `WriteBatch`, optional serializable txns ([fjall-rs/fjall](https://github.com/fjall-rs/fjall)) |
| `redb` | `>=4.1` | `[]` | storage feature `redb` — pure-Rust single-file CoW B+tree with typed `TableDefinition`; portable ([cberner/redb](https://github.com/cberner/redb)) |
| `rustreexo` | `>=0.5, <0.6` | `["std", "with-serde"]` | utreexo accumulators (`Stump`, `Pollard`, `MemForest`); 0.5 is current stable line, NOT 0.7 |
| `bitcoin_slices` | `>=0.11` | `["bitcoin", "sha2"]` | zero-alloc sans-I/O block visitor (the real crate behind the placeholder `bsl::` namespace; electrs uses it). Used by `crates/index` |
| `bdk_coin_select` | `>=0.4` | `[]` | BnB + knapsack + waste-metric coin selection for `crates/wallet` (replaces hand-rolling Bitcoin Core's C++ port) |
| `miniscript` | `>=13, <14` | `["std", "serde"]` | descriptors + miniscript (BIP380/381/382). 13.0.0 (2025-10) is current stable |
| `payjoin` | `>=1.0` | `[]` | OPTIONAL — BIP78/77; intentionally absent from `[workspace.dependencies]`; not yet wired, deferred to the wallet task |
| `quanta` | `>=0.12` | `[]` | TSC monotonic clock for hot-path p50/p95/p99 timing |
| `tracing` | `>=0.1.44, <0.2` | `["std", "attributes"]` | structured logging facade |
| `tracing-subscriber` | `>=0.3.23, <0.4` | `["std", "fmt", "registry", "ansi", "env-filter", "json", "smallvec", "tracing-log", "sharded-slab", "thread_local"]` | JSON to stderr + env filter |
| `metrics` | `>=0.24.6` | `[]` | metrics facade (no alloc on hot path) |
| `metrics-exporter-prometheus` | `>=0.18` | `[]` | Prometheus text exposition |
| `serde` | `>=1.0` | `["derive"]` | |
| `serde_json` | `>=1.0` | `["raw_value"]` | cold path (config, fixture loading) |
| `sonic-rs` | `>=0.5` | `[]` | SIMD JSON — 4-5× faster than `serde_json` on 1–100 KiB payloads; used by `crates/rpc` + `crates/electrum` on the hot path. Drop-in via `serde` traits ([cloudwego/sonic-rs](https://github.com/cloudwego/sonic-rs)) |
| `toml` | `>=1, <2` | `["parse", "display", "serde"]` | config (read-only) |
| `clap` | `>=4.6` | `["derive", "env", "wrap_help"]` | CLI; MSRV 1.95 matches |
| `signal-hook` | `>=0.4` | `[]` | sigterm/sigint; 0.4 latest |
| `rustls` | `>=0.23.40, <0.24` | `["std", "ring", "tls12", "logging"]` | TLS for Electrum listener; 0.23.40 latest; `ring` provider keeps one TLS stack |
| `rustls-pki-types` | `>=1.14` | `[]` | mandatory companion to `rustls` |
| `thiserror` | `>=2.0` | `[]` | every library crate's error type; 2.0.18 latest |
| `anyhow` | `>=1.0.100` | `[]` | `bin/bitcoin-rs` only (top-level `main()` error surfacing) |
| `portable-atomic` | `>=1.13` | `[]` | optional — 128-bit atomics for future lock-free counters; behind `feature = "portable-atomic"` |
| `proptest` | `>=1.11` | `[]` | property tests (dev-dep) |
| `proptest-derive` | `>=0.8` | `[]` | `#[derive(Arbitrary)]` for property tests (dev-dep) |
| `criterion` | `>=0.8` | `["html_reports"]` | benches (dev-dep); statistical p50/p95/p99 + HTML reports — `divan` is rejected for G14 because it lacks regression analysis |

**`clippy.toml`:**

```toml
msrv = "1.95.0"
cognitive-complexity-threshold = 15
type-complexity-threshold = 250
too-many-arguments-threshold = 8
disallowed-types = [
    { path = "std::sync::Mutex", reason = "use parking_lot::Mutex" },
    { path = "std::sync::RwLock", reason = "use parking_lot::RwLock" },
    { path = "std::collections::HashMap", reason = "use hashbrown::HashMap or HashTable" },
]
```

**`[workspace.lints.clippy]`** (in `Cargo.toml`): `pedantic = { level = "warn", priority = -1 }`, `nursery = { level = "warn", priority = -1 }`, `undocumented_unsafe_blocks = "deny"`, `as_conversions = "deny"`, `cast_lossless = "deny"`, `unwrap_used = "deny"`, `expect_used = "warn"`, `dbg_macro = "deny"`, `todo = "deny"`, `unimplemented = "deny"`, `mod_module_files = "deny"` (force `mod.rs`-free layout), plus 17 pedantic/nursery `allow` overrides: `module_name_repetitions`, `similar_names`, `must_use_candidate`, `missing_errors_doc`, `missing_panics_doc`, `struct_field_names` (pedantic noise), `option_if_let_else`, `significant_drop_tightening`, `redundant_pub_crate` (nursery items that fire on fine code), and `manual_let_else`, `format_push_string`, `missing_const_for_fn`, `collapsible_if`, `needless_continue`, `iter_without_into_iter`, `into_iter_without_iter` (Clippy 1.92 pedantic additions).

**`[workspace.lints.rust]`**: `unsafe_op_in_unsafe_fn = "deny"`, `missing_docs = "warn"`, `unreachable_pub = "warn"`.

---

## Verification Gates

All gates must pass before bitcoin-rs is shippable. Not phased — these are flat acceptance criteria.

**G1 — Headers-only sync parity.** `bitcoin-rs --network mainnet` → header chain hash matches `bitcoind`'s `getblockhash` for every height 0..tip.

**G2 — Full IBD UTXO root parity.** Every 10 000 blocks during IBD, our running coinstats hash matches Bitcoin Core's `gettxoutsetinfo` muhash field byte-for-byte.

**G3 — Kernel parity gate.** During the first 100 000 mainnet blocks of CI, every block is validated through *both* our Rust validator and `bitcoinkernel`. Any disagreement is a CI hard-fail; the failing block + log is artifacted.

**G4 — Consensus test vectors.** `tx_valid.json`, `tx_invalid.json`, `script_tests.json`, `sighash.json` from Bitcoin Core's `src/test/data/` are vendored into `crates/consensus/tests/vectors/` and run as `#[test]`s; 100 % pass.

**G5 — Electrum protocol parity.** Pointed at the same chain, our `crates/electrum` returns byte-identical responses to a reference electrs build for `blockchain.scripthash.{get_history,get_balance,subscribe,listunspent}`, `blockchain.transaction.get`, `blockchain.estimatefee`, `mempool.get_fee_histogram`, `server.{version,banner,donation_address,peers.subscribe}` over a 10 000-call random sample at tip — the sample size the G14 gate enforces (`EXPECTED_ELECTRUM_SAMPLE_SIZE = 10_000` in `bin/bitcoin-rs/tests/gates/g14_perf_budgets.rs`).

**G6 — Snapshot round-trip.** Driven in process through the snapshot API in `crates/utxo/src/snapshot.rs` (`write_snapshot`, then `read_snapshot_strict_v4`): reloading the written snapshot reproduces an identical UTXO set and coinstats hash. There is no CLI flag for this; the gate is `bin/bitcoin-rs/tests/gates/g06_snapshot_roundtrip.rs`, an `#[ignore]`d manual run over a populated UTXO set whose in-memory path is covered by `crates/utxo` unit tests. Format is `bitcoin-rs`'s own LE format (gocoin wire-compat dropped per ultrareview).

**G7 — Storage-backend equivalence.** RocksDB, MDBX (`signet-libmdbx`), fjall, and redb backends all pass G1–G6 with identical chain results. `cargo bench -p bitcoin-rs-storage --bench kvstore_backends` reports throughput + p99 latency for all four in `target/bench-report.md`. **Backend promotion rule:** if MDBX wins by ≥15 % on UTXO-commit p95 AND matches RocksDB on Electrum-history p95, MDBX becomes the new default in the next minor release and the change is documented in [docs/plans/2026-05-19-ultrareview-log.md](docs/plans/2026-05-19-ultrareview-log.md).

**G8 — Utreexo parity.** With `--utreexo-mode` (feature `utreexo`) enabled, IBD reproduces the same chain tip + coinstats hash as the rocksdb full-UTXO path.

**G9 — Wallet PSBT round-trip.** For every descriptor type (p2pkh, p2wpkh, p2sh-p2wpkh, p2tr, multisig, descriptor-wallet single-sig + multi-sig): wallet builds a PSBT, an external test signer signs it (test-only fixture key), wallet finalizes, RPC `sendrawtransaction` accepts. No private key ever passes through the wallet crate's public surface.

**G10 — Reorg-deep test.** Simulated 100-block reorg replays cleanly: UTXO state, coinstats, filter index, electrum index, wallet, mempool all converge to the new tip without panic, deadlock, or stale row. Verified against bitcoind's reorg behavior in regtest.

**G11 — Crash recovery.** `kill -9` during block commit; restart; node converges to the last fully-committed tip and reports no DB corruption (RocksDB / fjall / redb each tested).

**G12 — Graceful shutdown.** SIGTERM during IBD → all in-flight writes flush, RPC connections drain with 5 s deadline, snapshot written, exit code 0. Verified via `criterion` + a regression `#[test]` driving signal-hook.

**G13 — Lints clean.** `cargo +1.95.0 clippy -p bitcoin-rs --all-targets --no-default-features --features "$FEATURES" -- -D warnings` returns 0. `cargo +1.95.0 fmt --check` clean. `cargo deny check` clean.

**G14 — Performance budgets.**
- Initial block sync throughput is faster than Bitcoin Core's blocks-per-second on identical mainnet IBD (measured via `criterion`).
- UTXO commit p95 ≤ 50 ms per serialized block of at least 1 MB.
- Electrum `scripthash.get_history` p95 ≤ 30 ms over a 10 000-call random sample at tip.
- RSS ≤ 16 GiB at mainnet tip with fjall default + all indexes enabled.

**G15 — Workspace version sync.** Every internal `[workspace.dependencies]` path crate declares the same `version` as `[workspace.package].version` (`0.4.0`), asserted by `bin/bitcoin-rs/tests/gates/g15_workspace_version_sync.rs` so `target/release/bitcoin-rs --version` matches the manifest.

---

The 2026-06-05 campaign ledger moved to [docs/plans/2026-06-05-performance-campaign-ledger.md](docs/plans/2026-06-05-performance-campaign-ledger.md).

---

## Tasks

> Status: Tasks 0 through 19 and gates G1 through G15 are implemented on `main`. The unchecked step boxes below are the original construction record, not open work.

Task 0 bootstrap instructions were removed: the live workspace files are the record.

---

### Task 1: `crates/primitives` — types + encode/decode + hashing

**Files:**
- Create: `crates/primitives/src/{lib,hash,outpoint,tx,block,header,varint,network,sighash,encode}.rs`
- Test: `crates/primitives/tests/{golden,proptest}.rs`

The reference for layout and constants: `bitcoin/src/primitives/transaction.h`, `gocoin/lib/btc/btcdec.go`, `electrs/src/types.rs`. We do not re-derive shapes; we map them to Rust with `zerocopy` where the wire is fixed-size and `bitcoin` crate's types where it isn't.

- [ ] **Step 1: `Hash256` over `[u8; 32]` (`bytemuck::Pod`).** Methods: `from_le_bytes`, `to_le_bytes`, `from_str_be`, `to_string_be`, `as_byte_array`, `prefix8 -> [u8; 8]`. Property tests cover `from_str_be` ∘ `to_string_be` round-trip across 1 000 random inputs.

- [ ] **Step 2: `OutPoint { txid: Hash256, vout: u32 }`** — `zerocopy::AsBytes + FromBytes`; 36 bytes packed LE.

- [ ] **Step 3: `Varint` codec.** Decode `u64` from `&[u8]` advancing a cursor; encode `u64` into a `tinyvec::ArrayVec<u8, 9>`. Property tests round-trip 1 000 random `u64` values + boundary values `0`, `0xfc`, `0xfd`, `0xffff`, `0x10000`, `0xffff_ffff`, `0x1_0000_0000`, `u64::MAX`.

- [ ] **Step 4: `TxIn` + `TxOut` + `Tx` + `Block` + `BlockHeader`** — wrap `bitcoin::*` types where ergonomic, add zerocopy accessors where the layout permits. `Tx::txid()` and `Tx::wtxid()` use the active `sha2`/`bitcoin_hashes` dependency graph directly only if fresh G14 evidence proves a win over the `bitcoin` crate's compute path; panic if the input has SegWit witness data but no SegWit marker.

- [ ] **Step 5: `Network` enum** — `Mainnet`, `Testnet3`, `Testnet4`, `Signet`, `Regtest`. Constants: magic bytes, default ports, dns seeds, max target, retarget interval, genesis block hash.

- [ ] **Step 6: `Sighash`** — `All`, `None`, `Single`, `AllAnyoneCanPay`, …, `Default` (taproot). Compute per BIP143, BIP341, BIP342 — verified via `sighash.json` vectors from Core (vendored later in Task 2).

- [ ] **Step 7: Golden tests.** For 50 known mainnet blocks (heights 0, 1, 91722, 91812, 91842, 91880, 170, … selected for SegWit/taproot/duplicate-tx coverage), decode the block from `testdata/<height>.bin`, assert `block.block_hash()` matches the known hash and `tx.txid()` matches per-tx known hashes.

- [ ] **Step 8: `cargo test -p bitcoin-rs-primitives`** — must be green.

- [ ] **Step 9: Commit.**

```bash
git commit -am "feat(primitives): hash + outpoint + tx + block + sighash" -m "Op: extend"
```

---

### Task 2: `crates/consensus` — kernel-authoritative validator + parallel Rust path

**Files:**
- Create: `crates/consensus/src/{lib,kernel,rust_path,verify_tx,verify_block,bip9,bip30,bip34,bip65,bip66,bip68,bip112,bip113,bip141,bip143,bip341,bip342}.rs`
- Test: `crates/consensus/tests/{kernel_parity,vectors}.rs`
- Vendor: `crates/consensus/tests/vectors/{tx_valid,tx_invalid,script_tests,sighash}.json` (from Bitcoin Core `src/test/data/`)

- [ ] **Step 1: Vendor consensus vectors.** Copy from `~/dev/bitcoin-rs/bitcoin/src/test/data/{tx_valid,tx_invalid,script_tests,sighash}.json`. Commit verbatim with original SHA-256 documented in the commit body.

- [x] **Step 2: kernel transaction verification.** `KernelContext::new` and `KernelContext::verify_tx` remain the live bitcoinkernel harness Interface. The synthetic block-connection method was deleted after KTD1 rejected kernel-owned chainstate.

- [x] **Step 3: portable verification.** Stateless free functions in `verify_tx` and `verify_block` own portable validation; `rust_path` retains only the shared UTXO and tip-state contracts. The zero-caller object wrapper was deleted.

- [x] **Step 4: reject dual block connection.** KTD1 rejected the kernel/Rust `connect_block` comparison because kernel-owned chainstate would duplicate storage and invert the storage-equivalence gate. The dead dual-path module and both synthetic connection methods were deleted.

- [ ] **Step 5: BIP implementations.**
  - BIP9 versionbits state machine; thresholds + period from `Network`.
  - BIP30 duplicate-txid rejection (with the post-BIP34 carve-out exceptions for blocks 91722, 91812).
  - BIP34 coinbase height encoding.
  - BIP65 OP_CHECKLOCKTIMEVERIFY.
  - BIP66 strict DER signatures.
  - BIP68 relative locktime.
  - BIP112 OP_CHECKSEQUENCEVERIFY.
  - BIP113 median-time-past.
  - BIP141 segwit.
  - BIP143 segwit-v0 sighash.
  - BIP341 taproot.
  - BIP342 tapscript.

- [ ] **Step 6: `tx_valid.json` / `tx_invalid.json` runner** — iterate vectors, run both kernel and Rust path, assert agreement *and* expected verdict. Same for `script_tests.json`, `sighash.json`.

- [ ] **Step 7: `cargo test -p bitcoin-rs-consensus`** green.

- [ ] **Step 8: Commit.**

```bash
git commit -am "feat(consensus): kernel-authoritative validator + Rust parallel path + BIP suite" -m "Op: extend"
```

---

### Task 3: `crates/script` — interpreter (legacy / segwit / taproot)

**Files:**
- Create: `crates/script/src/{lib,interpreter,opcodes,stack,sigops,sighash_cache,taproot}.rs`
- Test: `crates/script/tests/{interpreter,proptest}.rs`

Port shape from `bitcoin/src/script/interpreter.cpp`. Stack is `tinyvec::ArrayVec<ScriptItem, 1000>` (MAX_STACK_DEPTH); script item is `enum ScriptItem { Num(i64), Bytes(SmallVec<[u8; 32]>) }`. Opcode dispatch is a flat `match` on `u8` — no jump table, no method lookup; LLVM produces a contiguous switch.

- [ ] **Step 1: Opcode constants** — copy from `bitcoin::blockdata::opcodes::all::*`, no re-derivation.

- [ ] **Step 2: `Interpreter::execute(&Script, &mut Stack, flags) -> Result<bool, ScriptError>`** — main loop. Each opcode is its own function; the `match` is the dispatcher.

- [ ] **Step 3: BIP66 strict-DER, BIP62 low-S** — per-rule, behind `flags`.

- [ ] **Step 4: Sigops counting** — legacy + segwit + taproot. Match Core's count exactly per vector.

- [ ] **Step 5: SigHashCache** — `bumpalo::Bump`-allocated; computed once per (sighash_type, anyone_can_pay) pair per tx-input.

- [ ] **Step 6: Taproot** — key-path + script-path; Schnorr verify via `secp256k1::verify_schnorr`; tapleaf/tapbranch hashing per BIP341.

- [ ] **Step 7: `script_tests.json` runner** — `crates/consensus`'s vector runner exercises this transitively, but a `crates/script`-local runner tests in isolation against `script_tests.json`.

- [ ] **Step 8: Batch Schnorr verify** — when block has ≥16 taproot inputs, batch via `secp256k1::verify_schnorr_batch`. Bench delta committed.

- [ ] **Step 9: Property tests** — random valid p2pkh / p2wpkh / p2tr → assemble + execute → assert success. Random invalid → assert failure.

- [ ] **Step 10: Commit.**

```bash
git commit -am "feat(script): interpreter + sigops + taproot + batch schnorr" -m "Op: extend"
```

---

### Task 4: `crates/storage` — pluggable KvStore (fjall default + rocksdb + mdbx + redb features)

**Files:**
- Create: `crates/storage/src/{lib,trait_,rocksdb_impl,mdbx_impl,fjall_impl,redb_impl,column_families,write_batch}.rs`
- Test: `crates/storage/tests/backend_equivalence.rs`
- Bench: `crates/storage/benches/kvstore_backends.rs`

- [ ] **Step 1: `KvStore` trait.**

```rust
pub trait KvStore: Send + Sync + 'static {
    type WriteBatch: WriteBatch;
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Option<Vec<u8>>;
    fn get_pinned(&self, cf: ColumnFamily, key: &[u8]) -> Option<impl AsRef<[u8]> + '_>;
    fn iter_prefix<'a>(&'a self, cf: ColumnFamily, prefix: &[u8]) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a>;
    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError>;
    fn flush(&self) -> Result<(), StorageError>;
    fn snapshot(&self) -> impl KvSnapshot + '_;
}

pub trait WriteBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]);
    fn delete(&mut self, cf: ColumnFamily, key: &[u8]);
    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]);
}
```

- [ ] **Step 2: `ColumnFamily` enum** — exactly electrs's 5 CFs: `TxConfirmed`, `TxMempool`, `BlockHeaders`, `Funding`, `Spending`. Plus `Coinstats`, `BlockTree`, `UtxoMeta` (snapshot ptrs). (`Filters`/`FilterHeaders` were specced for the removed BIP157/158 index; see issue #143.)

- [ ] **Step 3: RocksDB impl.** Mirror `electrs/src/db.rs` block-based options exactly (4 MiB blocks, lz4 compression, 256 MiB block-cache, bloom 10 bits/key, mt static). All CFs pre-created at open.

- [ ] **Step 4: MDBX impl (feature `mdbx`).** Via `signet-libmdbx >=0.8` (init4tech/mdbx). One `Environment` per database, one `Database` (LMDB-style sub-db) per CF. Use `EnvironmentBuilder::set_max_dbs(N)` for our CF count; `set_geometry` with lower/upper bound sized for a tip-resident UTXO + indexes (e.g. lower 1 GiB, upper 1 TiB, growth step 1 GiB). All writes go through a single `RwTransaction` per `KvStore::write` call — MDBX's single-writer model maps naturally to our batched commit shape. **Critical:** Reth + Erigon prove this works at Ethereum-mainnet scale (∼1.7 TiB live, billions of state entries); UTXO + indexes are well within the envelope. Document the wait-free reader semantics — Electrum queries do not block UTXO commits because MDBX readers operate on consistent MVCC snapshots without coordinating with the writer.

- [ ] **Step 5: fjall impl (feature `fjall`).** One `Keyspace`, one `Partition` per CF. Same write-batch semantics. Document the (real) flush-on-fsync differences in inline comments.

- [ ] **Step 6: redb impl (feature `redb`).** One `TableDefinition` per CF. Write-batches map to a single `WriteTransaction`.

- [ ] **Step 7: `backend_equivalence.rs` test** — for each backend: insert 10 000 rows across 5 CFs, read them back, prefix-iterate, delete-range; assert byte-identical results across backends.

- [ ] **Step 8: `crates/storage/benches/kvstore_backends.rs`** — criterion benchmark: write 1M sequential keys, write 1M random keys, point-get 1M keys, prefix-iter 100K-key prefix, 16-thread mixed-read-write workload. Report saved to `target/criterion/kvstore_backends/report/index.html` and an aggregate summary appended to `target/bench-report.md`.

- [ ] **Step 9: Commit.**

```bash
git commit -am "feat(storage): KvStore trait + fjall default + rocksdb + mdbx + redb features" -m "Op: extend"
```

---

### Task 5: `crates/utxo` — 256-shard HashTable over self-cell-pinned Bump

**Files:**
- Create: `crates/utxo/src/{lib,key,record,shard,set,snapshot,defrag}.rs`
- Test: `crates/utxo/tests/{commit_roundtrip,reorg,snapshot_roundtrip,defrag_invariants}.rs`
- Bench: `crates/utxo/benches/utxo_commit.rs`

- [ ] **Step 1: `UtxoKey`** — `[u8; 8]` (TXID prefix), wrapped over `nohash_hasher::NoHashHasher` so the hasher is identity. Identity-hashed is safe here because TXID prefixes are themselves uniform.

- [ ] **Step 2: `UtxoRecord`** — gocoin shape: `vout_bitmap: u64` (which vouts of the originating tx remain unspent), `vouts: tinyvec::ArrayVec<OneUtxoOut, 8>` (overflows to heap), where `OneUtxoOut = { vout: u32, value: u64, script_pubkey_offset: u32, script_pubkey_len: u16 }`. Script bytes live in the shard's arena; `script_pubkey_offset` is the byte offset into the arena slab.

- [ ] **Step 3: `Shard`** — `self_cell!`:

```rust
self_cell::self_cell! {
    pub struct ShardCell {
        owner: Box<bumpalo::Bump>,
        #[covariant]
        dependent: ShardTable,
    }
}

pub struct ShardTable<'arena> {
    pub table: hashbrown::HashTable<&'arena UtxoRecord>,
    pub byte_arena_high_water: usize,
    pub deleted: u32,
}

pub struct Shard {
    inner: parking_lot::RwLock<ShardCell>,
    // padded to one cache line
}

pub struct UtxoSet {
    shards: [CachePadded<Shard>; 256],
}
```

`Box<Bump>` pin means the arena address is stable even after the `Shard` is moved into the array slot, so `&'arena UtxoRecord` is sound; `self_cell` enforces this at compile time.

- [ ] **Step 4: `UtxoSet::commit_block(&self, changes: &BlockChanges, block_hash: &BlockHash)`** — bucket additions by `add.txid[0]` shard, batch in 32-op groups (mirror gocoin's `OPS_AT_ONCE = 32`), take *one* shard write-lock per shard per block, drain its add+remove sets, then release. `rayon::scope` parallelizes across shards. Single write-lock per shard per block bounds writer-starvation for Electrum readers.

- [ ] **Step 5: `UtxoSet::get(&self, op: &OutPoint) -> Option<TxOut>`** — read-lock the shard, find via `HashTable::find`, deserialize the specific vout. Returns an owned `TxOut`.

- [ ] **Step 6: `UtxoSet::undo_block(&self, undo: &UndoBatch)`** — reverse a commit.

- [ ] **Step 7: `UtxoSet::defrag_one_shard(&self)`** — round-robin, take write lock, rebuild `HashTable::with_capacity(live)` when `deleted / table.len() > 1/4`. Window bounded by `live * 16ns`; amortized at 1 Hz across 256 shards, so a reader's stall is `~ live/256 * 16ns / s`.

- [ ] **Step 8: Snapshot format (bitcoin-rs native, LE throughout).**

```
header:      [magic u32 = 0x55_54_58_4F][version u32][tip_hash [u8; 32]][height u32][record_count u64]
record:      [shard_idx u8][key_prefix [u8; 8]][vout_bitmap u64][vout_count u8][vouts …]
each vout:   [vout u32][value u64][script_len u16][script bytes]
trailer:     [muhash3072 [u8; 384]]
```

Serialized via `zerocopy::AsBytes` where layout permits; script bytes are length-prefixed. Snapshot dump/load is a separate path that streams to a file via `io::BufWriter` (8 MiB buffer).

- [ ] **Step 9: `crates/utxo/tests/commit_roundtrip.rs`** — populate 10 000 entries, `get()` all 10 000, assert exact match.

- [ ] **Step 10: `crates/utxo/tests/reorg.rs`** — apply 10 blocks, `undo_block` 5, assert state matches first-5-blocks.

- [ ] **Step 11: `crates/utxo/tests/snapshot_roundtrip.rs`** — dump, load into a fresh set, assert identical state + identical muhash trailer.

- [ ] **Step 12: `crates/utxo/tests/defrag_invariants.rs`** — random commits with ~50 % deletions, repeatedly `defrag_one_shard`, assert no entries vanish.

- [ ] **Step 13: `crates/utxo/benches/utxo_commit.rs`** — criterion: commit synthetic 4 MiB blocks at 10 k input + 10 k output density; report p50 / p95 / p99 + entries-per-shard distribution.

- [ ] **Step 14: Commit.**

```bash
git commit -am "feat(utxo): 256-shard self_cell HashTable + commit/get/undo/defrag/snapshot" -m "Op: extend"
```

---

### Task 6: `crates/utreexo` — Pollard + Stump + MemForest + bridge-node

**Files:**
- Create: `crates/utreexo/src/{lib,accumulator,proof,bridge}.rs`
- Test: `crates/utreexo/tests/proof_roundtrip.rs`

- [ ] **Step 1: Wrap `rustreexo::accumulator::{stump::Stump, pollard::Pollard, mem_forest::MemForest}`** behind a thin trait `Utreexo` so the rest of the workspace doesn't directly depend on `rustreexo`.

- [ ] **Step 2: Proof attach/verify** — input proofs are deserialized via `rustreexo::Proof`; verify before applying to the accumulator.

- [ ] **Step 3: Bridge-node mode** — generate proofs for blocks our node ingests; expose them on the p2p extension `utreexo` wire messages (per `utreexod/wire/udata.go`).

- [ ] **Step 4: `crates/utreexo/tests/proof_roundtrip.rs`** — synthesize 100 blocks, generate proofs, apply to a fresh `Stump`, assert root matches.

- [ ] **Step 5: Integration with `crates/utxo`** — when `--utreexo` mode is active, `UtxoSet` shrinks to a per-block in-memory cache rather than the full set; lookups against historical UTXOs fall through to the accumulator proof attached to the input.

- [ ] **Step 6: Commit.**

```bash
git commit -am "feat(utreexo): Pollard + Stump + MemForest + bridge" -m "Op: extend"
```

---

### Task 7: `crates/chain` — block tree (Slab + ArcSwapOption tip + ruint chainwork)

**Files:**
- Create: `crates/chain/src/{lib,node,tree,tip,header_sync,reorg}.rs`
- Test: `crates/chain/tests/{reorg_deep,header_sync_roundtrip}.rs`

- [ ] **Step 1: `NodeId(u32)`** + `BlockTreeNode { parent: Option<NodeId>, height: u32, hash: Hash256, header: BlockHeader, chainwork: ruint::Uint<256, 4>, status: NodeStatus }`.

- [ ] **Step 2: `BlockTree { nodes: Slab<BlockTreeNode>, by_hash: HashTable<NodeId>, tip: ArcSwapOption<TipSnapshot> }`**.

- [ ] **Step 3: `TipSnapshot { tip_id: NodeId, height: u32, chainwork: ruint::Uint<256, 4> }`** — atomically swapped on every accepted-tip change.

- [ ] **Step 4: Header sync** — port `utreexod/blockchain/chain.go` shape. Accept headers in batches of 2 000, validate PoW, validate continuity, insert.

- [ ] **Step 5: Reorg** — walk forks via parent pointers, find common ancestor, detach blocks from old tip → new tip, undo / connect on `UtxoSet` accordingly. Reorg-deep test in Task 19 / G10.

- [ ] **Step 6: Persistence** — block tree backed by `crates/storage::BlockTree` CF: one row per `NodeId` keyed by `Hash256`.

- [ ] **Step 7: Commit.**

```bash
git commit -am "feat(chain): block tree + tip swap + chainwork + reorg" -m "Op: extend"
```

---

### Task 8: `crates/index` — port electrs verbatim (embedded; no Daemon)

**Files:**
- Create: `crates/index/src/{lib,db,types,index,status,mempool}.rs`
- Test: `crates/index/tests/parity_against_electrs.rs`

Strategy: port `electrs/src/{db,index,types,status,mempool}.rs` literally to our `KvStore` abstraction. Shape unchanged; substitute `electrs`'s direct rocksdb for our `KvStore` trait. The 5-CF layout, 12-byte `HashPrefixRow`, and `bitcoin_slices::Visitor` block-walking shape are all preserved.

- [ ] **Step 1: `HashPrefixRow`** — `[u8; 8]` script-hash prefix + `[u8; 4]` height. `zerocopy::AsBytes + FromBytes`.

- [ ] **Step 2: Mirror electrs `IndexEntry`, `FundingEntry`, `SpendingEntry`, `TxConfirmed`, `TxMempool`** verbatim.

- [ ] **Step 3: `Indexer` struct** — same shape as `electrs/src/index.rs::Indexer`, but its constructor takes `Arc<dyn KvStore>` not a direct `DB`.

- [ ] **Step 4: `bitcoin_slices::Visitor`** — bring in `bitcoin_slices >=0.11` (features `["bitcoin", "sha2"]`) and visit blocks once for indexing rather than full decode. This is the real crate name behind electrs's `bsl` namespace.

- [ ] **Step 5: `crates/index/tests/parity_against_electrs.rs`** — run a reference electrs and our index over the same 1 000 blocks; assert identical row sets per CF (sorted byte-equal).

- [ ] **Step 6: Commit.**

```bash
git commit -am "feat(index): port electrs to KvStore-backed embedded indexer" -m "Op: extend"
```

---

### Task 10: running muhash3072 for O(1) gettxoutsetinfo

**Files:**
- Create: `crates/coinstats/src/{lib,muhash3072}.rs`. Merged into
  `crates/utxo/src/stats/` by issue #164: statistics are derived computation over
  the UTXO state that crate already owns, and the separate package added a
  dependency edge without a boundary.
- Test: `crates/utxo/tests/{muhash_unit,coin_stats_roundtrip,snapshot_with_muhash}.rs`

- [ ] **Step 1: `MuHash3072`** — 3072-bit multiplicative hash, group elements over residues mod `2^3072 - r`. Port from `bitcoin/src/crypto/muhash.cpp` exactly (constant-time mul + inv).

- [ ] **Step 2: `CoinStats { muhash: MuHash3072, height: u32, total_amount: u64, bogo_size: u64, …}`** updated on each `commit_block`.

- [ ] **Step 3: Persist `CoinStats` to `Coinstats` CF** keyed by `height`.

- [ ] **Step 4: Parity test** — run `bitcoind --txindex` to height 100 000; dump its `gettxoutsetinfo --hash-type=muhash`; compare against ours at the same height.

- [ ] **Step 5: Commit.**

```bash
git commit -am "feat(coinstats): muhash3072 running + O(1) gettxoutsetinfo" -m "Op: extend"
```

---

### Task 11: block + undo pruner

**Files:**
- Create: `crates/pruning/src/{lib,policy,block_pruner,undo_pruner}.rs`. Merged
  into `crates/storage/src/pruning/` by issue #164: pruning is a retention
  policy over rows `storage` already owns, and the separate crate declared
  three dependencies it never referenced. The utreexo-only coordinator went
  with the utreexo mode (issue #144).
- Test: `crates/storage/tests/prune_then_reorg.rs`

- [ ] **Step 1: `PrunePolicy { target_size_mb: u64, keep_below_tip: u32 }`** — match Core's `-prune=` semantics.

- [ ] **Step 2: `BlockPruner`** — walks block storage, deletes blocks below `tip - keep_below_tip` whose total stored size exceeds target.

- [ ] **Step 3: `UndoPruner`** — same for undo data; never prunes undo for blocks above the last 288 (Core's reorg safety margin).

- [ ] **Step 4: Utreexo-only mode** — when `--utreexo --prune=0` (interpreted as "keep only the accumulator, no blocks"), block storage is fully discarded after the block is indexed + filter-indexed + UTXO-committed.

- [ ] **Step 5: `prune_then_reorg.rs`** — prune at depth 200, force a 100-block reorg, assert chain converges (pruned blocks are not needed; they're below the reorg horizon).

- [ ] **Step 6: `utreexo_no_blocks.rs`** — start with `--utreexo --prune=0`, IBD to height 10 000, assert no block bytes on disk except headers.

- [ ] **Step 7: Commit.**

```bash
git commit -am "feat(pruning): block + undo pruner + utreexo-only mode" -m "Op: extend"
```

---

### Task 12: `crates/mempool` — Pareto-front by-fee; RBF; package eviction

**Files:**
- Create: `crates/mempool/src/{lib,entry,pool,pareto,rbf,eviction,policy}.rs`
- Test: `crates/mempool/tests/{rbf_bip125,ancestor_limits,pareto_ordering}.rs`

- [ ] **Step 1: `MempoolEntry { tx, vsize, fee, ancestor_size, ancestor_fee, descendant_size, descendant_fee, time, height }`**.

- [ ] **Step 2: `ParetoFront`** — port from `gocoin/client/mining/mining.go`'s Pareto-front priority queue; backed by `tinyvec::ArrayVec<MempoolEntryId, 256>` per fee-bucket.

- [ ] **Step 3: Funding/spending indexes** — `BTreeSet<(ScriptHash, MempoolEntryId)>` (Electrum needs prefix scans).

- [ ] **Step 4: RBF (BIP125)** — verify replacement satisfies rules 1–6; evict superseded entries + their descendants.

- [ ] **Step 5: Ancestor/descendant limits** — default Core values: 25 ancestors / 101 KvB / 25 descendants.

- [ ] **Step 6: Package eviction** — when memory exceeds target, evict lowest-fee-rate ancestor packages until under budget.

- [ ] **Step 7: BIP125 vector tests** — table of `{base_tx, replacement_tx, expected_verdict}` covering rules 1–6; assert.

- [ ] **Step 8: Commit.**

```bash
git commit -am "feat(mempool): Pareto-front + RBF + ancestor/descendant + package eviction" -m "Op: extend"
```

---

### Task 13: `crates/p2p` — peer FSM; addrv2; BIP339; ban-score

**Files:**
- Create: `crates/p2p/src/{lib,peer,fsm,addrv2,inv,wtxid,banlist,handshake,compactblocks}.rs`
- Test: `crates/p2p/tests/handshake_roundtrip.rs`

- [ ] **Step 1: Wire codec** — port `btcd/wire/` shape via `zerocopy` + `bitcoin` crate's `consensus::encode`. Bounded read via `crossbeam-channel` so a slow peer can't OOM the daemon.

- [ ] **Step 2: Peer FSM** — `Disconnected → VersionExchange → Verack → Ready → Disconnecting`.

- [ ] **Step 3: BIP130 sendheaders, BIP339 wtxid relay, BIP155 addrv2** all negotiated in version handshake.

- [ ] **Step 4: BIP152 compact-block-relay** opt-in handshake; high-bandwidth + low-bandwidth modes.

- [ ] **Step 5: `BanList`** — score-based per-peer (Core's `MAX_BAN_SCORE = 100`); persistence to disk.

- [ ] **Step 6: Inbound dispatch** — `version`, `verack`, `ping`/`pong`, `inv`, `getheaders`, `headers`, `getblocks`, `block`, `tx`, `getdata`, `notfound`, `addr`/`addrv2`, `getaddr`, `mempool`, `filterload`/`filteradd`/`filterclear` (BIP37 — accept but ignore), `cfheaders`/`cfilter`/`getcfheaders`/`getcfilter`/`getcfcheckpt` (BIP157 — decoded, never served).

- [ ] **Step 7: Outbound peer manager** — DNS-seed bootstrap, addrman shape, 8 outbound + 2 block-only + 117 inbound default capacity.

- [ ] **Step 8: Commit.**

```bash
git commit -am "feat(p2p): peer FSM + wtxid relay + addrv2 + ban-score + BIP152" -m "Op: extend"
```

---

### Task 14: `crates/wallet` — PSBT builder + descriptors + coin selection; NO signing

**Files:**
- Create: `crates/wallet/src/{lib,descriptor,watcher,psbt,coin_selection,fee_bump,signer_iface}.rs`
- Test: `crates/wallet/tests/{psbt_roundtrip,coin_selection,fee_bump}.rs`

**Critical contract:** wallet has **zero** private-key surface. No fn takes `SecretKey`, no fn returns `SecretKey`, no struct stores `SecretKey`. Signing is delegated to an external `Signer` impl that the caller injects:

```rust
pub trait ExternalSigner: Send + Sync {
    /// Implementation lives outside the daemon — MPC service, HWI, hardware wallet, air-gapped device, etc.
    fn sign_psbt(&self, psbt: &Psbt) -> Result<Psbt, SignerError>;
}
```

The daemon never instantiates an `ExternalSigner` itself; the RPC layer routes signing requests to a configured external service.

- [ ] **Step 1: Descriptor support** via `miniscript` crate. Parse + validate: `pkh(...)`, `wpkh(...)`, `sh(wpkh(...))`, `tr(...)`, `wsh(multi(...))`, `tr(multi_a(...))`. Derive addresses for each descriptor index range.

- [ ] **Step 2: `Watcher` struct** — `descriptors: Vec<Descriptor>`; subscribes to the script-hash index for matches; maintains an in-process address → UTXO list.

- [ ] **Step 3: PSBT v2 (BIP370) builder.** `PsbtBuilder::new().add_input(prev_utxo, descriptor_index).add_output(addr, amount).finalize() -> Psbt`. No signing — the PSBT is returned unsigned.

- [ ] **Step 4: Coin selection** — `bdk_coin_select >=0.4` provides BnB + knapsack + waste-metric. Wire it in directly rather than porting Bitcoin Core's C++ `coinselection.cpp` — `bdk_coin_select` is the canonical Rust implementation (used in BDK, audited, BIP-aligned). Wrap behind `wallet::select_coins(targets: &Target, candidates: &[Candidate], strategy: SelectStrategy) -> Selection` so the dep can be swapped without touching call sites.

- [ ] **Step 5: Fee bumping (RBF / CPFP).** `wallet.bump_fee(txid, new_fee_rate)` — replaces input PSBT, increases fee, respects BIP125 rules.

- [ ] **Step 6: Finalize signed PSBT.** `wallet.finalize_signed(psbt) -> Result<Tx, FinalizeError>` — takes a *signed* PSBT (signed externally), extracts witness scripts, produces final `Tx`. Internal sanity check: every input has signatures matching the descriptor's required policy.

- [ ] **Step 7: `psbt_roundtrip.rs`** — for each descriptor type: build PSBT → external test signer (in `tests/fixtures/` only; never compiled into the wallet crate) → finalize → assert valid `Tx` that `consensus::verify_tx` accepts.

- [ ] **Step 8: Grep guard.** CI grep step ensures `SecretKey` is never imported into `crates/wallet/src/`:

```bash
! grep -r "SecretKey\|secp256k1::Secret\|seckey" crates/wallet/src
```

This fails the build if a private-key type leaks in.

- [ ] **Step 9: Commit.**

```bash
git commit -am "feat(wallet): descriptors + PSBT v2 + coin selection + fee bump; NO signing" -m "Op: extend"
```

---

### Task 15: `crates/mining` — getblocktemplate (BIP22/23)

**Files:**
- Create: `crates/mining/src/{lib,template,policy,coinbase}.rs`
- Test: `crates/mining/tests/template_against_core.rs`

- [ ] **Step 1: `MiningPolicy`** — pulls Pareto front from mempool, packs tx into 4 MiB weight, computes coinbase value (subsidy + fees).

- [ ] **Step 2: `BlockTemplate`** per BIP22 — JSON shape exactly matching Core's response.

- [ ] **Step 3: Coinbase template** — extranonce reserve range, witness commitment per BIP141.

- [ ] **Step 4: `template_against_core.rs`** — at a given mempool state, our template's tx selection matches Core's within a tunable tolerance (ordering must match for blocks with no fee ties; ties may differ).

- [ ] **Step 5: Commit.**

```bash
git commit -am "feat(mining): getblocktemplate BIP22/23 + policy" -m "Op: extend"
```

---

### Task 16: `crates/rpc` — Bitcoin-Core-compat JSON-RPC subset

**Files:**
- Create: `crates/rpc/src/{lib,server,handlers,auth,error,types}.rs`
- Test: `crates/rpc/tests/{handler_smoke,core_compat}.rs`

RPC surface (Core-compat for tooling):

- `getblockchaininfo`, `getblockcount`, `getblockhash`, `getbestblockhash`
- `getblock`, `getblockheader`, `getblockstats`
- `getrawtransaction`, `gettxout`, `gettxoutproof`, `verifytxoutproof`
- `gettxoutsetinfo` — O(1) via coinstats
- `sendrawtransaction`, `testmempoolaccept`
- `getmempoolinfo`, `getmempoolentry`, `getrawmempool`, `getmempoolancestors`, `getmempooldescendants`
- `estimatesmartfee`, `estimaterawfee`
- `getnetworkinfo`, `getpeerinfo`, `addnode`, `disconnectnode`, `getconnectioncount`, `getnettotals`
- `getblocktemplate`, `submitblock`, `prioritisetransaction`
- `getdescriptorinfo`, `deriveaddresses`, `scantxoutset` (wallet-adjacent — no signing)
- `walletcreatefundedpsbt`, `walletprocesspsbt`, `finalizepsbt`, `combinepsbt` (all PSBT — no signing; signing is rejected with a `-32603` "wallet has no private keys; use external signer" error)
- `bumpfee` (PSBT-only)

- [ ] **Step 1: JSON-RPC 1.0 + 2.0 over HTTP** — hand-rolled minimal sync HTTP/1.1 server (the JSON-RPC framework landscape is async/tokio-only as of 2026-05; `jsonrpc-core` is deprecated; `tiny_http` is stale). Basic auth + cookie auth. Long-poll for `getblocktemplate`. Connection accept on `std::net::TcpListener`; per-connection thread.

- [ ] **Step 2: Per-handler thin wrapper** — input parse via `sonic-rs >=0.5` (SIMD JSON, 4-5× faster than `serde_json` on 1–100 KiB payloads — measured in the source's benchmarks), dispatch into the relevant crate, format response via `sonic-rs::to_string`. Cold paths (config-shaped, debug-only RPCs) fall back to `serde_json` via the same `serde::Serialize` impls.

- [ ] **Step 3: `core_compat.rs` test** — for a fixed regtest fixture, every supported RPC returns Core-compatible JSON (key set, types, ordering).

- [ ] **Step 4: Commit.**

```bash
git commit -am "feat(rpc): Bitcoin Core-compat JSON-RPC subset (no signing)" -m "Op: extend"
```

---

### Task 17: `crates/electrum` — Electrum protocol over the index

**Files:**
- Create: `crates/electrum/src/{lib,server,session,methods,subscription}.rs`
- Test: `crates/electrum/tests/parity_against_electrs.rs`

- [ ] **Step 1: TCP/TLS server** — port shape from `electrs/src/electrum.rs`. Per-session line-delimited JSON-RPC parsed with `sonic-rs`. TLS via `rustls >=0.23` + `rustls-pki-types >=1.14` (modern pure-Rust TLS stack; tokio-free).

- [ ] **Step 2: Methods** — `server.{version,banner,donation_address,peers.subscribe,ping}`, `blockchain.scripthash.{get_history,get_balance,subscribe,listunspent}`, `blockchain.transaction.{get,broadcast}`, `blockchain.estimatefee`, `mempool.get_fee_histogram`, `blockchain.block.headers`, `blockchain.headers.subscribe`.

- [ ] **Step 3: Status hashes** — `electrs/src/status.rs` shape; subscriptions push status updates on every relevant chain/mempool change.

- [ ] **Step 4: `parity_against_electrs.rs`** — see G5.

- [ ] **Step 5: Commit.**

```bash
git commit -am "feat(electrum): protocol surface over embedded index" -m "Op: extend"
```

---

### Task 18: `crates/node` — event loop + config + signals + metrics + tracing

**Files:**
- Create: `crates/node/src/{lib,event_loop,config,bitcoin_conf_compat,signal,metrics,logging,shutdown}.rs`
- Test: `crates/node/tests/{shutdown,crash_recovery}.rs`

- [ ] **Step 1: `Config`** — TOML + CLI (clap) + env (`BITCOIN_RS_*`). `bitcoin.conf` compatibility layer that parses Core's `bitcoin.conf` format into our `Config` for the overlapping option set (`-prune`, `-rpcuser`, `-rpcpassword`, `-server`, `-listen`, `-txindex`, `-dbcache`, …). Conflicts resolved in order: CLI > env > TOML > bitcoin.conf > defaults.

- [ ] **Step 2: Event loop** — single `crossbeam-channel::Select` over: `p2p_inbound`, `p2p_outbound`, `rpc_request`, `electrum_request`, `mempool_tick` (1 Hz), `defrag_tick` (1 Hz), `metrics_scrape` (10 s), `shutdown_signal`.

- [ ] **Step 3: Structured logging via `tracing`** — JSON output to stderr by default; `RUST_LOG`-compatible filtering; per-module log levels in config.

- [ ] **Step 4: Prometheus metrics** — IBD progress (height + headers), p2p (peers connected, bytes in/out), mempool (size, bytes), block validation (latest block time + duration), RPC (req/s, p95 latency), UTXO (entries, shards over-occupancy), storage (per-CF size).

- [ ] **Step 5: Signal handling** — SIGTERM / SIGINT trigger graceful shutdown: stop accepting new connections, drain RPC + Electrum sessions with 5 s deadline, flush all in-flight UTXO commits to storage, write a final snapshot, exit 0.

- [ ] **Step 6: Crash recovery** — on startup, detect partial commits (last block's UTXO writes not flushed); replay from the last fully-committed tip recorded in `UtxoMeta` CF; assert convergence by re-validating the next N blocks and comparing coinstats.

- [ ] **Step 7: `shutdown.rs` test** — drive `signal-hook` SIGTERM, assert clean exit + final snapshot present.

- [ ] **Step 8: `crash_recovery.rs` test** — `kill -9` during commit (via `libc::raise(SIGKILL)` in a child process); restart; assert chain tip matches the last fully-committed block, no corruption.

- [ ] **Step 9: Commit.**

```bash
git commit -am "feat(node): event loop + config + signals + metrics + tracing + crash recovery" -m "Op: extend"
```

---

### Task 19: `bin/bitcoin-rs` — main binary

**Files:**
- Create: `bin/bitcoin-rs/src/main.rs`
- Create: `bin/bitcoin-rs/Cargo.toml`

- [ ] **Step 1: `main.rs`** — `#[global_allocator] static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;` + `fn main() -> ExitCode { bitcoin_rs_node::run(Config::from_args_env_file()) }`.

- [ ] **Step 2: `Cargo.toml`** — depends only on `bitcoin-rs-node` and `mimalloc` and `anyhow`.

- [ ] **Step 3: `cargo build --release`** — produces `target/release/bitcoin-rs` (single binary, statically linked except for kernel C++ + rocksdb C++).

- [ ] **Step 4: Smoke run** — `target/release/bitcoin-rs --regtest --rpcport=18443` boots, RPC `getblockchaininfo` returns regtest height 0.

- [ ] **Step 5: Commit.**

```bash
git commit -am "feat(bin): bitcoin-rs binary" -m "Op: extend"
```

---

### Task 20: Verification gates G1–G15 — flat acceptance suite

**Files:**
- Create: `bin/bitcoin-rs/tests/gates/{g01_headers_only_sync,g02_ibd_muhash_parity,g03_kernel_parity,g04_consensus_vectors,g05_electrum_parity,g06_snapshot_roundtrip,g07_storage_equivalence,g08_utreexo_parity,g09_wallet_psbt_roundtrip,g10_reorg_deep,g11_crash_recovery,g12_graceful_shutdown,g13_lints_clean,g14_perf_budgets,g15_workspace_version_sync}.rs`
- CI: `.github/workflows/ci.yml`

Each gate is a `#[test]` under `bin/bitcoin-rs/tests/gates/`. Most are `#[ignore]`d manual gates that need live peers or externally collected evidence; G14 verifies the externally collected evidence contract (gathered by the `scripts/run-g14-*.sh` drivers) and fails closed when it is missing. CI (`.github/workflows/ci.yml`) runs the non-ignored gates in the workspace test lane. Plan is "done" when all 15 gates are green for two consecutive CI runs on `main`.

- [ ] **Step 1–15:** Each gate test as defined in *Verification Gates* above. Each in its own file under `bin/bitcoin-rs/tests/gates/` (`g01_headers_only_sync.rs` through `g15_workspace_version_sync.rs`), each callable independently via `cargo test -p bitcoin-rs --test g<N>_<name>`, with `-- --ignored --nocapture` for the manual gates.

- [ ] **Step 16: CI matrix** — runs gates against `--no-default-features --features rocksdb`, `--no-default-features --features fjall`, `--no-default-features --features redb` (G7).

- [ ] **Step 17: Commit.**

```bash
git commit -am "test(gates): verification gates G1-G15" -m "Op: extend"
```

---

The 2026-05-19 Ultrareview Log moved to [docs/plans/2026-05-19-ultrareview-log.md](docs/plans/2026-05-19-ultrareview-log.md).

---

## Execution Handoff

**Ordering rule:** Tasks 0 → 20 in sequence. No parallel implementation of dependent tasks. Verification gates G1–G15 (Task 20) gate the project as "done" — bitcoin-rs is not shippable until every gate is green for two consecutive CI runs on `main`.

**Workspace setup:** The plan's `bitcoin-rs/` subdirectory lives inside the workspace; reference repos (`gocoin/`, `electrs/`, `utreexod/`, `bitcoin/`, `btcd/`) remain readable from the cwd parent.

**Done definition:** All 21 tasks committed, all 15 verification gates green twice on `main`, `cargo +1.95.0 clippy -p bitcoin-rs --all-targets --no-default-features --features "$FEATURES" -- -D warnings` clean, `cargo deny check` clean, `cargo +1.95.0 fmt --check` clean, `target/release/bitcoin-rs --version` prints `0.4.0`, IBD to mainnet tip completes with G2 + G3 + G14 all reporting green.
