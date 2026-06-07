# bitcoin-rs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement task-by-task. Steps use checkbox (`- [ ]`) syntax. **Do not split phases or roadmaps** — every task in this plan must ship before bitcoin-rs is declared done.

**Goal:** Ship `bitcoin-rs` — a single-binary ultra-fast Bitcoin full node in Rust 2024. Natively-integrated UTXO (gocoin shape), Electrum-style index (electrs shape), utreexo accumulator (utreexod shape), in-process wallet (PSBT builder; **no private keys, no signing**), in-process mining (getblocktemplate), pruning, BIP157/158 compact filters, coinstats index, four pluggable storage backends (RocksDB / MDBX / fjall / redb), SIMD JSON on the RPC hot path. All production polish (graceful shutdown, ban-score, crash recovery, metrics, structured logging, config) is part of core scope.

**Architecture:** One process. One `crossbeam-channel`-driven event loop (no tokio/async-std). UTXO held as 256 shards of `hashbrown::HashTable<ArenaRef<'arena>>` over `bumpalo::Bump`, arenas pinned via `self_cell!` so the lifetime is sound (not transmuted), each shard guarded by `parking_lot::RwLock` and `CachePadded` against false sharing. Block tree as `slab::Slab<Node>` + `u32 NodeId`; tip published via `arc_swap::ArcSwapOption<TipSnapshot>`; chainwork as `ruint::Uint<256,4>`. Consensus *borrowed* from `bitcoinkernel >=0.2, <0.3` (default-on, alpha-but-load-bearing) — our Rust validator runs in parallel and is asserted byte-identical to kernel for every accepted block. Wallet is in-process PSBT builder + descriptor watcher with **zero private-key surface**: external signers receive a PSBT, return a signed PSBT, finalize happens inside the daemon. Storage is a `KvStore` trait with **fjall as the launch default**; RocksDB, `signet-libmdbx` (MDBX — Reth/Erigon-proven memory-mapped CoW B+tree), and `redb` (pure-Rust B+tree) live behind cargo features. All four backends are gated by G7 backend-equivalence.

**Tech stack:** Rust 2024 edition, MSRV 1.95.0, resolver `"3"`. `mimalloc` global allocator; allocator and non-UTXO hasher alternates require fresh G14 evidence before promotion. See the full Dependency Table below for the vetted floor list; every entry was audited against crates.io / GitHub on 2026-05-19 and pins to the latest stable line. The audit summary lives in the *Ultrareview Log* at the bottom.

---

## Design Principles

1. **KISS first.** Reach for the simplest data structure that fits the access pattern. Complexity is paid for by benchmarks, not aesthetics.
2. **Minimal allocations on hot paths.** Block validation, UTXO commit, header sync, p2p inbound — none of these may allocate per item. Arenas, slabs, `tinyvec`, `smallvec`, `compact_str` cover the common cases.
3. **Zero-copy where the wire allows.** Inbound p2p frames, on-disk records, snapshot files all use `zerocopy` / `bytemuck` over `Vec<u8>::copy_from_slice` when the layout is fixed.
4. **Hot path stack-allocated.** Validation / script verify / merkle / UTXO lookup use `[u8; N]`, `MaybeUninit`, `tinyvec::ArrayVec` for bounded fan-out.
5. **Zig-style scratch arenas.** Thread-local `bumpalo::Bump`, `Bump::reset()` on block boundary (no `Drop` calls). Per-shard arenas live until shutdown and are pinned via `self_cell!`.
6. **Pre-allocate.** Any `Vec`/`HashMap` whose final size is knowable uses `with_capacity` + `push_within_capacity`.
7. **Unsafe when it pays its way.** `unsafe` is permitted wherever a bench shows a genuine win. Every `unsafe` block carries a `// SAFETY:` rationale (enforced via `clippy::undocumented_unsafe_blocks = deny`) and a one-line bench delta in the commit body (`Δp95: NNμs → MMμs`). Prefer `zerocopy` / `NonNull<T>` / `bumpalo` shapes when they match the win; reach for raw `unsafe` when they don't.
8. **Best-of-breed data structures.** UTXO map: `hashbrown::HashTable` over `Box<bumpalo::Bump>` pinned via `self_cell!`. Block tree: `slab::Slab<Node>` + `u32 NodeId`. Chainwork compare: `ruint::Uint<256, 4>`. Mempool by-fee: gocoin's Pareto-front priority queue on `tinyvec::ArrayVec`. Mempool funding/spending: `BTreeSet` (Electrum needs prefix range scans). SHA-256 follows the current manifest: `sha2 >=0.11, <0.12` and `bitcoin_hashes >=0.14.100, <0.15`; any SHA acceleration change requires fresh G14 evidence against that dependency graph. Non-UTXO hashing: `foldhash` default; `gxhash` opt-in behind an `x86_64-aes` runtime check; `nohash-hasher` for UTXO key (8-byte TXID prefix is already uniform).
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
├── LICENSE                       # MIT/Apache-2.0 dual
├── deny.toml                     # cargo-deny config
├── .github/workflows/ci.yml      # fmt + clippy -D warnings + test + bench-smoke + deny
├── benches/                      # cross-crate criterion (UTXO, script, header sync)
│   ├── utxo_commit.rs
│   ├── script_verify.rs
│   ├── header_sync.rs
│   └── kvstore_backends.rs       # rocksdb vs mdbx vs fjall vs redb
├── crates/
│   ├── primitives/               # Hash256, OutPoint, Tx, Block, Header, varint, network, sighash types
│   ├── consensus/                # kernel-authoritative validator + parallel Rust path
│   ├── script/                   # interpreter (legacy/segwit/taproot/sighash variants/sigops)
│   ├── storage/                  # KvStore trait + fjall default + rocksdb + mdbx + redb feature impls
│   ├── utxo/                     # 256-shard HashTable + Bump + self_cell + RwLock; commit/get/undo/defrag/snapshot
│   ├── utreexo/                  # rustreexo Pollard/Stump/MemForest; proof attach/verify; bridge-node
│   ├── chain/                    # Slab<BlockTreeNode>+u32 NodeId; ArcSwapOption tip; ruint chainwork; reorg
│   ├── index/                    # port electrs verbatim (embedded; 5 CFs; HashPrefixRow; bitcoin_slices visitor)
│   ├── filters/                  # BIP157 cfheaders + BIP158 GCS encoding + filter index
│   ├── coinstats/                # running muhash3072; O(1) gettxoutsetinfo
│   ├── pruning/                  # block-file + undo-file pruner; utreexo-only mode coordinator
│   ├── mempool/                  # Pareto-front by-fee; RBF (BIP125); package eviction; ancestor/descendant limits
│   ├── p2p/                      # peer FSM; addrv2; wtxid relay (BIP339); ban-score; compact-block-relay (BIP152) opt
│   ├── wallet/                   # descriptors (BIP380/381/382); PSBT v2 builder (BIP370); coin selection via bdk_coin_select; fee bump (RBF); NO signing
│   ├── mining/                   # getblocktemplate (BIP22/23); mining policy from mempool; coinbase template
│   ├── rpc/                      # Bitcoin-Core-compat JSON-RPC subset
│   ├── electrum/                 # Electrum protocol over the index
│   └── node/                     # event loop; config (TOML + bitcoin.conf compat + CLI + env); signal handling; metrics; tracing; graceful shutdown
└── bin/
    └── bitcoin-rs/               # main.rs; thin — wires `crates/node`
```

Each crate's `Cargo.toml` inherits `package.rust-version`, `package.edition`, and lints from `workspace`. No crate ships its own `[lints]` block.

---

## Tech-Stack Dependency Table

Stored once in `bitcoin-rs/Cargo.toml` under `[workspace.dependencies]`. Per-crate `Cargo.toml` files re-declare with `<dep>.workspace = true`.

| Dep | Floor | Features | Notes |
|---|---|---|---|
| `mimalloc` | `>=0.1.50` | `[]` | `#[global_allocator]` in `bin/bitcoin-rs`; latest 0.1.50 (2026-04) [purpleprotocol/mimalloc_rust](https://github.com/purpleprotocol/mimalloc_rust) |
| `bitcoinkernel` | `>=0.2, <0.3` | `[]` | default-on consensus authority; active manifest line. Plan accepts the alpha cost because parity gating is the load-bearing safety net. |
| `bitcoin` | `>=0.32, <0.33` | `["serde", "rand-std", "secp-recovery", "std"]` | encode/decode + types. Stay on stable 0.32.x; 0.33 is still `0.33.0-beta` as of 2026-05 — wait for final |
| `secp256k1` | `>=0.31` | `["recovery", "rand-std", "serde", "global-context"]` | latest stable 0.31.x; 0.32 is still beta. Batch Schnorr `verify_schnorr_batch` available in 0.31+ |
| `sha2` | `>=0.11, <0.12` | `[]` | active manifest line; 0.11 exposes no `std`/`asm` feature, so SHA acceleration changes require fresh G14 evidence |
| `bitcoin_hashes` | `>=0.14.100, <0.15` | `["std"]` | active manifest line aligned with `bitcoin 0.32`; 0.14 exposes no `asm` feature and 1.0 breaks the current bitcoin-io graph |
| `hashbrown` | `>=0.17` | `["inline-more", "default-hasher", "nightly"]` (nightly behind `feature = "nightly-hashbrown"`) | `HashTable` API is the stable raw-insertion API (the old `raw-entry` API is deprecated); MSRV 1.95 matches |
| `bumpalo` | `>=3.20` | `["collections"]` | per-shard + thread-local scratch arenas with `Bump::reset()` on block boundary |
| `self_cell` | `>=1.2.2` | `[]` | proc-macro-free; pins `Box<Bump>` address so `HashTable<&'arena T>` is sound across moves |
| `ruint` | `>=1.12` | `["alloc"]` | `Uint<256, 4>` for chainwork (constant-time compare beats heap-allocated bignums) |
| `slab` | `>=0.4` | `["serde"]` | `Slab<BlockTreeNode>` keyed by `u32 NodeId` |
| `arc_swap` | `>=1.9` | `[]` | tip snapshot RCU; 1.9.1 latest |
| `parking_lot` | `>=0.13` | `["arc_lock", "send_guard"]` | per-shard `RwLock`; the `disallowed-types` clippy rule below routes every accidental `std::sync::*` here |
| `crossbeam-channel` | `>=0.5.15` | `[]` | event loop `Select`; non-negotiable for the architecture |
| `crossbeam-utils` | `>=0.8` | `[]` | `CachePadded` against false sharing on shard array |
| `crossbeam-skiplist` | `>=0.1` | `[]` | reserved for mempool fallback path |
| `rayon` | `>=1.12` | `[]` | block-parallel script verify via `rayon::scope` |
| `foldhash` | `>=0.2` | `[]` | default hasher (non-UTXO); 0.2 latest; explicit `BuildHasher` everywhere |
| `gxhash` | `>=3.4` | `[]` | opt-in `[features] gxhash = ["dep:gxhash"]` — runtime AES-NI probe + fallback to foldhash |
| `nohash-hasher` | `>=0.2` | `[]` | identity hasher for the UTXO key (8-byte TXID prefix is uniform-by-construction) |
| `rapidhash` | `>=4.1` | `[]` (dev-dep only) | candidate non-UTXO hasher for future G14 comparison; promoted only if a clean measured win materializes |
| `tinyvec` | `>=1.11` | `["alloc"]` | primary `ArrayVec` for hot paths (100 % safe, no unsafe); mempool Pareto entries, sighash cache slots |
| `smallvec` | `>=1.15` | `["union", "const_generics"]` | spill-tolerant cases only; `arrayvec` is rejected as effectively frozen |
| `compact_str` | `>=0.9` | `[]` | SSO string for Electrum method names + tag strings |
| `bytemuck` | `>=1.25` | `["derive"]` | `Pod` + `Zeroable` on fixed-layout wire types |
| `zerocopy` | `>=0.8` | `["derive"]` | 0.8 is a trait-rewrite vs 0.7 — `TryFromBytes`/`IntoBytes`/`FromBytes` + `KnownLayout`/`Immutable`/`Unaligned` markers. Use exclusively for snapshot records + zerocopy on-disk index rows |
| `lz4_flex` | `>=0.11` | `[]` | pure-Rust LZ4 for snapshot + custom-format compression (rocksdb feature already pulls C zstd) |
| `rust-rocksdb` | `>=0.49` | `["mt_static", "snappy", "lz4", "zstd"]` | storage feature `rocksdb`; zaidoon1 fork is the active maintained binding (0.49.1 2026-05) |
| `signet-libmdbx` | `>=0.8` | `[]` | storage feature `mdbx` — init4tech/mdbx fork of reth-libmdbx; Reth + Erigon + Silkworm + Akula all use libmdbx in production. Memory-mapped CoW B+tree, wait-free readers, no WAL. **Strong candidate for default after G7 benchmarks**. License MIT/Apache-2.0 ([crates.io/signet-libmdbx](https://crates.io/crates/signet-libmdbx)) |
| `fjall` | `>=3.1` | `[]` | storage **default** — pure-Rust LSM with multi-keyspace (column families), `WriteBatch`, optional serializable txns ([fjall-rs/fjall](https://github.com/fjall-rs/fjall)) |
| `redb` | `>=4.1` | `[]` | storage feature `redb` — pure-Rust single-file CoW B+tree with typed `TableDefinition`; portable ([cberner/redb](https://github.com/cberner/redb)) |
| `rustreexo` | `>=0.5` | `[]` | utreexo accumulators (`Stump`, `Pollard`, `MemForest`); 0.5 is current stable line, NOT 0.7 |
| `bitcoin_slices` | `>=0.11` | `["bitcoin", "sha2"]` | zero-alloc sans-I/O block visitor (the real crate behind the placeholder `bsl::` namespace; electrs uses it). Used by `crates/index` |
| `bdk_coin_select` | `>=0.4` | `[]` | BnB + knapsack + waste-metric coin selection for `crates/wallet` (replaces hand-rolling Bitcoin Core's C++ port) |
| `miniscript` | `>=13` | `[]` | descriptors + miniscript (BIP380/381/382). 13.0.0 (2025-10) is current stable |
| `payjoin` | `>=1.0` | `[]` | OPTIONAL — gated behind `feature = "payjoin"` (default off). BIP78/77; not core, but cheap to wire when the dep is on the table |
| `quanta` | `>=0.12` | `[]` | TSC monotonic clock for hot-path p50/p95/p99 timing |
| `tracing` | `>=0.1.41` | `[]` | structured logging facade |
| `tracing-subscriber` | `>=0.3.23` | `["env-filter", "json", "fmt"]` | JSON to stderr + env filter |
| `metrics` | `>=0.24.6` | `[]` | metrics facade (no alloc on hot path) |
| `metrics-exporter-prometheus` | `>=0.18` | `[]` | Prometheus text exposition |
| `serde` | `>=1.0` | `["derive"]` | |
| `serde_json` | `>=1.0` | `["raw_value"]` | cold path (config, fixture loading) |
| `sonic-rs` | `>=0.5` | `[]` | SIMD JSON — 4-5× faster than `serde_json` on 1–100 KiB payloads; used by `crates/rpc` + `crates/electrum` on the hot path. Drop-in via `serde` traits ([cloudwego/sonic-rs](https://github.com/cloudwego/sonic-rs)) |
| `toml` | `>=0.8` | `[]` | config (read-only) |
| `clap` | `>=4.6` | `["derive", "env", "wrap_help"]` | CLI; MSRV 1.95 matches |
| `signal-hook` | `>=0.4` | `[]` | sigterm/sigint; 0.4 latest |
| `rustls` | `>=0.23` | `["std"]` | TLS for Electrum listener; 0.23.40 latest |
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

**`[workspace.lints.clippy]`** (in `Cargo.toml`): `pedantic = { level = "warn", priority = -1 }`, `nursery = { level = "warn", priority = -1 }`, `undocumented_unsafe_blocks = "deny"`, `as_conversions = "deny"`, `cast_lossless = "deny"`, `unwrap_used = "deny"` (exempt tests), `expect_used = "warn"`, `dbg_macro = "deny"`, `todo = "deny"`, `unimplemented = "deny"`, `print_stdout = "deny"` (exempt bin), `print_stderr = "deny"` (exempt bin), `mod_module_files = "deny"` (force `mod.rs`-free layout).

**`[workspace.lints.rust]`**: `unsafe_op_in_unsafe_fn = "deny"`, `missing_docs = "warn"`, `unreachable_pub = "warn"`.

---

## Verification Gates

All gates must pass before bitcoin-rs is shippable. Not phased — these are flat acceptance criteria.

**G1 — Headers-only sync parity.** `bitcoin-rs --headers-only mainnet` → header chain hash matches `bitcoind`'s `getblockhash` for every height 0..tip.

**G2 — Full IBD UTXO root parity.** Every 10 000 blocks during IBD, our running coinstats hash matches Bitcoin Core's `gettxoutsetinfo` muhash field byte-for-byte.

**G3 — Kernel parity gate.** During the first 100 000 mainnet blocks of CI, every block is validated through *both* our Rust validator and `bitcoinkernel`. Any disagreement is a CI hard-fail; the failing block + log is artifacted.

**G4 — Consensus test vectors.** `tx_valid.json`, `tx_invalid.json`, `script_tests.json`, `sighash.json` from Bitcoin Core's `src/test/data/` are vendored into `crates/consensus/tests/vectors/` and run as `#[test]`s; 100 % pass.

**G5 — Electrum protocol parity.** Pointed at the same chain, our `crates/electrum` returns byte-identical responses to a reference electrs build for `blockchain.scripthash.{get_history,get_balance,subscribe,listunspent}`, `blockchain.transaction.get`, `blockchain.estimatefee`, `mempool.get_fee_histogram`, `server.{version,banner,donation_address,peers.subscribe}` over a 1 000-scripthash random sample.

**G6 — Snapshot round-trip.** `bitcoin-rs --snapshot-dump /tmp/utxo.snap && bitcoin-rs --snapshot-load /tmp/utxo.snap` reproduces an identical UTXO set and coinstats hash. Format is `bitcoin-rs`'s own LE format (gocoin wire-compat dropped per ultrareview).

**G7 — Storage-backend equivalence.** RocksDB, MDBX (`signet-libmdbx`), fjall, and redb backends all pass G1–G6 with identical chain results. `cargo bench --bench kvstore_backends` reports throughput + p99 latency for all four in `target/bench-report.md`. **Backend promotion rule:** if MDBX wins by ≥15 % on UTXO-commit p95 AND matches RocksDB on Electrum-history p95, MDBX becomes the new default in the next minor release and the change is documented in the ultrareview log.

**G8 — Utreexo parity.** With `--utreexo` enabled, IBD reproduces the same chain tip + coinstats hash as the rocksdb full-UTXO path.

**G9 — Wallet PSBT round-trip.** For every descriptor type (p2pkh, p2wpkh, p2sh-p2wpkh, p2tr, multisig, descriptor-wallet single-sig + multi-sig): wallet builds a PSBT, an external test signer signs it (test-only fixture key), wallet finalizes, RPC `sendrawtransaction` accepts. No private key ever passes through the wallet crate's public surface.

**G10 — Reorg-deep test.** Simulated 100-block reorg replays cleanly: UTXO state, coinstats, filter index, electrum index, wallet, mempool all converge to the new tip without panic, deadlock, or stale row. Verified against bitcoind's reorg behavior in regtest.

**G11 — Crash recovery.** `kill -9` during block commit; restart; node converges to the last fully-committed tip and reports no DB corruption (RocksDB / fjall / redb each tested).

**G12 — Graceful shutdown.** SIGTERM during IBD → all in-flight writes flush, RPC connections drain with 5 s deadline, snapshot written, exit code 0. Verified via `criterion` + a regression `#[test]` driving signal-hook.

**G13 — Lints clean.** `cargo +1.95.0 clippy -p bitcoin-rs --all-targets --no-default-features --features "$FEATURES" -- -D warnings` returns 0. `cargo +1.95.0 fmt --check` clean. `cargo deny check` clean.

**G14 — Performance budgets.**
- Initial block sync throughput is faster than Bitcoin Core's blocks-per-second on identical mainnet IBD (measured via `criterion`).
- UTXO commit p95 ≤ 50 ms per 4 MiB block.
- Electrum `scripthash.get_history` p95 ≤ 30 ms over a 10 000-call random sample at tip.
- RSS ≤ 16 GiB at mainnet tip with fjall default + all indexes enabled.

---

## Current Performance Campaign Status (2026-06-05)

This section tracks the aggressive sync/UTXO performance campaign that has landed on `origin/main`.
It is a status addendum to the roadmap below, not a replacement for the all-up shippability gates.
Do not mark the broad roadmap tasks complete from these slices alone unless the named gate evidence exists.

**Merged into `origin/main`:**

- [x] Node sync request scheduling was compressed with bounded peer selection, FIFO staged-block eviction, collapsed received-block scans, fused getdata cache construction, alternate-peer retries for expired blocks, contiguous received-scan candidates, inbound drain batching, inbound wakeups, and retry-metric coalescing.
  Evidence commits: `ff2f211`, `74dafc0`, `d868d80`, `90b76b2`, `ec0c5e8`, `46846e1`, `a11b811`, `be99fc4`, `8a5cca6`.
- [x] Node sync peer selection now skips saturated selected-peer scans when a candidate cannot enter the top-N request list, preserving equal-height order while shrinking many-peer scheduler ticks.
  Evidence commit: `e2f766e`.
- [x] Node apply-path hot spots were compressed with UTXO change txid conversion hoisting, cached apply-hash slice drains, and related block-apply scan reductions.
  Evidence commits: `7a337b3`, `196c63c`.
- [x] Node UTXO-change assembly was compressed by hoisting per-transaction coinbase classification out of the output/removal branches.
  Evidence commit: `97d9a75`.
- [x] Node UTXO-change assembly now skips same-block-spend membership probes when `ApplyScratch` proves the block has no same-block spends.
  Evidence commit: `c3c258c`.
- [x] Node BIP68 apply-path planning was compressed by lazy-allocating the prevout-MTP cache only for time-based sequence locks and removing the unused non-coinbase input-count accumulator.
  Evidence commit: `0c9394d`.
- [x] Node BIP68 apply-path planning was compressed again by skipping the full same-block metadata overlay pass when a block has no version-2 inputs with BIP68 enabled.
  Evidence commit: `3c60937`.
- [x] Consensus block-rule merkle validation was compressed by fusing merkle-root calculation and merkle-mutation detection into one in-place pass.
  Evidence commit: `ae04303`.
- [x] UTXO listener/commit hot paths were compressed with ordered listener event collection, order-independent listener coalescing, coalesced listener event preallocation, small listener shard commit coalescing, serial listener error-vec removal, fast deletion for fully spent records, and listener-aware full-record spend removal.
  Evidence commits: `15bd917`, `87141a3`, `80806a3`, `cfb0c74`, `316738b`, `13ab475`, `6262a8d`.
- [x] UTXO committed-event batches now cache their output-level operation count, avoiding a listener-side event-vector rescan before CoinStats chunking decisions.
  Evidence commit: `124c5ad`.
- [x] Coinstats hot helpers were compressed with private MuHash helper inlining, event-delta helper inlining, and ChaCha final-state add unrolling.
  Evidence commits: `84e8645`, `cdbeb07`, `4ebcfce`.
- [x] Coinstats listener aggregation was compressed for large coalesced UTXO event batches with bounded parallel chunks, plus a no-listener two-shard attribution benchmark.
  Evidence commit: `da9e31c`.
- [x] Coinstats MuHash insert hot paths were compressed with measured private arithmetic-helper inlining.
  Evidence commit: `0b39026`.
- [x] Coinstats direct listener batches were compressed with thresholded parallel insert/remove reductions for large single-shard batches.
  Evidence commit: `4540052`.
- [x] Coinstats small committed event batches were compressed by using serial delta reduction below the parallel chunk threshold, with a 512-entry two-shard listener benchmark guard.
  Evidence commit: `d5718e9`.
- [x] Coinstats committed-event batches were retuned so 64+ operation blocks use bounded 32-op parallel event chunks, shrinking the spend-heavy sync proxy without changing consensus validation.
  Evidence commit: `dd8e9bb`.
- [x] UTXO low-shard no-listener commits now group txid-local bucket runs behind an 8-shard gate, with an interleaved same-txid churn benchmark guarding the duplicate-heavy shape and existing/uniform guard benches checked.
  Evidence commit: `dd8e9bb`.
- [x] UTXO fully-spent record deletion was compressed from two hash-table probes to one occupied-entry probe.
  Evidence commit: `7e8f194`.
- [x] Performance evidence scaffolding was expanded with a mainnet prefix replay measurement example.
  Evidence commit: `2234ad5`.
- [x] Node sync received-block handling now defers unsolicited-block height resolution to rare retry/drop paths, removing an eager block-tree lookup from the hot received-scan path.
  Evidence commit: `0dd244e`.
- [x] UTXO key hot helpers now use explicit inline annotations without changing the `NoHashHasher` table-hash value, shrinking spend-heavy apply and guarded UTXO commit shapes.
  Evidence commit: `b85ad05`.
- [x] Block staging eviction now removes selected FIFO eviction candidates from the received-order queue immediately, avoiding repeated stale-entry cleanup on received-scan paths without changing retry semantics.
  Evidence commit: `cd353f2`.
- [x] Block-tree active-chain height lookups now use a private active-height index for published-tip requests, removing deep parent-pointer walks from sync getdata construction without changing fork fallback semantics.
  Evidence commit: `2db5c4e`.
- [x] Block staging inserts now use a single vacant-entry hash-table probe for new received blocks, avoiding the previous contains-then-insert double lookup while preserving duplicate and retry behavior.
  Evidence commit: `4d10d85`.
- [x] Buffered sync apply now stores applied block hashes in the existing inline `ExpectedBlockHashes` buffer, removing one heap allocation from the contiguous staged-apply tick without changing retry or failure handling.
  Evidence commit: `7d18912`.
- [x] Buffered sync apply now advances the expected-apply cache with an offset cursor instead of front-draining cached hashes, avoiding repeated hash-buffer shifts across staged apply ticks.
  Evidence: Criterion `production_state_partial_apply_tick_128_blocks` -10.564% on first patched comparison; repeat showed `production_state_128_blocks` -4.7655% and `production_state_apply_tick_128_blocks` -2.1743%.
- [x] Buffered sync apply now defers its apply-latency timestamp until staged blocks are actually ready, removing an unused `Instant::now()` call from no-ready sync ticks without changing the recorded apply latency window for ready blocks.
  Evidence commit: `dd9995a`.
- [x] Empty staged-block ticks now return before timeout pruning and apply-readiness checks, shrinking many-peer scheduler ticks while preserving stale-prune and contiguous-apply behavior.
  Evidence commit: `7e7421e`; Criterion `many_peers_512` -2.6818%, deep-header pure/indexed unchanged, production-state within noise.
- [x] Coinstats committed-event chunk staging now uses inline storage for small parallel listener reductions, removing one heap allocation from common two-shard listener batches without changing event order or UTXO semantics.
  Evidence commit: `42479b8`.
- [x] G14 Criterion artifact production now binds supplied elapsed seconds to exact raw Criterion benchmark sections, rejecting elapsed/raw mismatches, non-exact benchmark labels, and unlabeled timing lines before artifact creation.
  Evidence commit: `2db4124`; `cargo test -p bitcoin-rs --test g14_perf_evidence_script --no-default-features --features rocksdb,fjall,redb` passed 34/34.
- [x] G14 Criterion measurement now has a runner that captures raw canonical `bitcoin-rs/mainnet-ibd` and `bitcoin-core/mainnet-ibd` command output, parses elapsed seconds, delegates artifact validation, forwards bitcoin-cli args, and removes partial outputs on failure.
  Evidence commit: `d84a84f`; `cargo test -p bitcoin-rs --test g14_perf_evidence_script --no-default-features --features rocksdb,fjall,redb,mdbx,bitcoinconsensus` passed 36/36.
- [x] G14 Criterion evidence now binds each artifact benchmark entry to a raw output path, verifies raw-output hashes at manifest/collector time, and re-parses canonical Criterion elapsed seconds from archived raw output before accepting faster-than-Core evidence.
  Evidence command: `cargo test -p bitcoin-rs --test g14_perf_evidence_script --no-default-features --features rocksdb,fjall,redb,mdbx,bitcoinconsensus`.
- [x] The final G14 ignored gate now requires and reports the raw Criterion output path/hash fields exported by the collector, preserving raw-output custody in the accepted gate transcript without claiming the live faster-than-Core run is complete.
  Evidence command: `cargo test -p bitcoin-rs --test g14_perf_budgets -- --ignored --nocapture` with synthetic current-HEAD G14 env.
- [x] Deterministic sync proxy coverage now includes in-order inbound block delivery, isolating the common successful IBD receive/apply path from the existing out-of-order and oversized-burst stress shapes.
  Evidence: Criterion `deterministic_initial_sync_proxy_in_order_inbound_128_blocks` completed at `1.8655ms` for 128 in-order inbound blocks.
- [x] Deterministic sync proxy coverage now includes the G14-relevant fjall/all-index production shape, exercising real chainstate, txindex, and compact-filter fjall stores instead of only the previous no-index production fixture.
  Evidence: Criterion `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_128_blocks` completed at `6.7892ms` for 128 deterministic blocks with `--no-default-features --features fjall`.
- [x] Deterministic sync proxy coverage now includes a spend-heavy fjall/all-index production shape, exercising fanout spends through real chainstate, txindex, and compact-filter fjall stores.
  Evidence: Criterion `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_spend_heavy` completed at `99.810ms` for the 117-block, 1,141-transaction spend-heavy proxy with `--no-default-features --features fjall`.
- [x] Deterministic sync proxy coverage now includes fjall/all-index staged apply ticks, closing the previous gap where contiguous and cached apply-tick benches used only the no-index production fixture.
  Evidence: Criterion `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_apply_tick_128_blocks` completed with `7.6994ms` mean and `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_partial_apply_tick_128_blocks` completed with `5.1307ms` mean under `--no-default-features --features fjall`.
- [x] Apply-stage diagnostics now include staged fjall/all-index sync wrapper attribution, comparing `BlockSync::apply_buffered_blocks` histogram sums against per-block `apply_block` totals for the same final staged tick.
  Evidence: `cargo bench -p bitcoin-rs-node --bench sync_apply_metrics --no-default-features --features fjall` reported contiguous staged all-index apply `sync_apply_buffered_sum_ms=3.2607`, `apply_total_sum_ms=3.1758`, `sync_wrapper_gap_ms=0.0849`; partial cached staged all-index apply reported `1.7894`, `1.7424`, and `0.0470`, respectively.
- [x] Apply-stage diagnostics now include the spend-heavy fjall/all-index workload, identifying UTXO/CoinStats commit work as the dominant measured stage before further all-index sync optimization.
  Evidence: `cargo bench -p bitcoin-rs-node --no-default-features --features fjall --bench sync_apply_metrics` reported `spend_heavy_117_all_indexes` at `78.375296ms` total elapsed, `0.6688ms` average apply total, with `utxo_commit_avg_ms=0.4980`, `tx_index_ingest_avg_ms=0.0660`, and `filter_index_avg_ms=0.0080`.
- [x] Direct spend-heavy UTXO diagnostics now isolate the all-index apply bottleneck to CoinStats listener commit work rather than raw table mutation.
  Evidence: `cargo bench -p bitcoin-rs-node --no-default-features --features fjall --bench sync_apply_metrics` reported `utxo_spend_heavy_117_no_listener` at `0.0994ms` average commit time and `utxo_spend_heavy_117_listener` at `0.4896ms`, while the same run's `spend_heavy_117_all_indexes` reported `utxo_commit_avg_ms=0.5711`.
- [x] MuHash element generation now writes ChaCha20 block output directly into accumulator limbs, removing the intermediate block-word array from each per-coin hash.
  Evidence: `cargo bench -p bitcoin-rs-coinstats --bench coinstats_hotpath` reported `coinstats/muhash_remove_preencoded_8192` -4.3542% and `coinstats/listener_remove_coins_8192` -5.2163%; targeted rerun of `coinstats/utxo_commit_listener_two_shard_8192` reported -21.531%; `sync_apply_metrics` repeat reported `spend_heavy_117_all_indexes` at `0.7247ms` average total with `utxo_commit_avg_ms=0.5350`.
- [x] MuHash element generation now builds the constant/key ChaCha20 base state once per coin and only patches the counter for each output block, preserving byte-equivalent ChaCha limbs while reducing per-coin element setup.
  Evidence: same-session `coinstats_hotpath` moved `coinstats/muhash_insert_preencoded_8192` -5.9531% and `coinstats/muhash_remove_preencoded_8192` -3.1031%; three-run `sync_apply_metrics` post-change median for `spend_heavy_117_all_indexes` was `0.6094ms` average total with `utxo_commit_avg_ms=0.4598` against current baseline `0.6648ms` / `0.4953`; `cargo test -p bitcoin-rs-coinstats --no-fail-fast` passed the ChaCha byte-stream and MuHash reference-oracle tests.
- [x] CoinStats coalesced listener events now use smaller Rayon chunks only for wide multi-shard batches, preserving the narrow-batch chunk size while exposing more parallel MuHash delta work on spend-heavy fanout blocks.
  Evidence: pre-change `sync_apply_metrics` reported `spend_heavy_117_all_indexes` at `0.7258ms` average total with `utxo_commit_avg_ms=0.5144`; post-change repeat reported `0.6257ms` average total with `utxo_commit_avg_ms=0.4650`; targeted `coinstats/utxo_commit_listener_spend_fanout_64` reported `1.2569ms`, and `coinstats/utxo_commit_listener_two_shard_8192` reported -15.368%.
- [x] CoinStats singleton committed removals now call the per-coin delta remover directly instead of routing through a one-element removal batch, shrinking listener removal hotspots without changing MuHash/accounting inputs.
  Evidence: Criterion `coinstats/utxo_commit_listener_spend_fanout_64` -7.4918%, `coinstats/utxo_commit_listener_two_shard_512` -6.3205%, and `coinstats/utxo_commit_listener_two_shard_8192` -23.831%; same-machine sync guards stayed neutral-to-slightly-positive with full fjall/all-index 128 blocks `6.7431ms` clean versus `6.7108ms` patched, partial staged apply `5.0208ms` clean versus `4.9860ms` patched, contiguous staged apply `6.5158ms` clean versus `6.5342ms` patched, and spend-heavy all-index reporting no significant change.
- [x] Txindex funding-row ingest now checks OP_RETURN directly from serialized script bytes instead of wrapping each output script in a `bitcoin::Script` view before hashing non-OP_RETURN outputs.
  Evidence: pre-change `sync_apply_metrics` reported `spend_heavy_117_all_indexes` at `0.6759ms` average total with `tx_index_ingest_avg_ms=0.0723`; post-change repeats reported `0.6097ms`/`0.5425ms` average total with `tx_index_ingest_avg_ms=0.0596`/`0.0472`.
- [x] Txindex pending hash-prefix rows now stay in typed row form until batch write, removing one fixed-size row-byte copy during block ingest while preserving electrs row bytes.
  Evidence: clean-run `sync_apply_metrics` baseline reported `spend_heavy_117_all_indexes` at `0.6731ms` average total with `tx_index_ingest_avg_ms=0.0760`; post-change repeat reported `0.6351ms` average total with `tx_index_ingest_avg_ms=0.0617`.
- [x] Node block-source height lookups now use a dense active-chain index fast path before the existing binary-search rewind fallback, preserving duplicate-height record semantics.
  Evidence: Criterion `block_source_height_lookup_tail_4096` -8.5845%; production-state sync proxies stayed within noise.
- [x] Buffered sync apply now checks for an expected-apply cache before loading chain/applied tip snapshots, avoiding unnecessary `ArcSwap` loads on no-cache apply ticks.
  Evidence: Criterion `production_state_128_blocks` -4.6290%, `production_state_apply_tick_128_blocks` -2.2947%, and `production_state_partial_apply_tick_128_blocks` -3.7774%; `many_peers_512` unchanged.
- [x] Block staging inserts now skip the overflow-eviction helper on the common within-budget path, avoiding unnecessary helper entry and empty dropped-vector construction without changing eviction order.
  Evidence: Criterion `deep_headers_received_scan_128_blocks` -4.4914% and `production_state_128_blocks` -5.0979%; reverse-scan overflow, oversized inbound burst, many-peer, apply-tick, and partial-apply guards stayed within noise.
- [x] Block-body persistence now uses an owned `Bytes` write-batch fast path from the already serialized block buffer, avoiding one Rust-side body-sized batch copy while preserving backend write ordering.
  Evidence commit: `b49d61a`; storage block-body benches improved RocksDB direct puts by -3.1938%, redb direct puts by -6.5534%, and redb batch puts by -20.672%; `sync_apply_metrics` reported `spend_heavy_117_all_indexes` at `0.5811ms` average total with `block_body_persist_avg_ms=0.0047`.
- [x] Block staging full drains now clear stale received-order and deadline metadata when no received blocks remain, avoiding retained FIFO/deadline state across successful staged-apply ticks without changing restore-tail ordering.
  Evidence: Criterion `deep_headers_pure_128_blocks` -2.5513%, `deep_headers_indexed_128_blocks` -5.0847%, and `deep_headers_received_scan_128_blocks` -10.844%; production-state, apply-tick, partial-apply, reverse-scan overflow, many-peer, and oversized inbound guards stayed within noise on the broader deterministic proxy rerun.
- [x] Node apply-path duplicate-spend planning now sizes the spent-outpoint conflict set for spend-heavy multi-transaction blocks, avoiding growth in the common spend-heavy proxy shape without changing membership semantics.
  Evidence: Criterion `sync_pipeline_apply_spend_heavy_proxy` -6.4981%, `sync_pipeline_apply_spend_heavy_proxy_filter` -6.2339%, and `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_spend_heavy` -9.1276%; all reported `p = 0.00 < 0.05`.
- [x] Txindex row construction now computes the block-height little-endian bytes once per block visitor and reuses them for txid, spending, and funding rows, preserving electrs row bytes while removing repeated per-row height encoding.
  Evidence: same-session clean `sync_apply_metrics` baseline reported `spend_heavy_117_txindex` at `0.7161ms` average total with `tx_index_ingest_avg_ms=0.0861` and `spend_heavy_117_all_indexes` at `0.6611ms` / `tx_index_ingest_avg_ms=0.0681`; patched repeat reported `0.6138ms` / `0.0665` and `0.6175ms` / `0.0635`.
- [x] The default no-ZMQ apply tail now skips the post-commit block/transaction notification loop when the publisher is explicitly unobservable, preserving configured/custom publisher behavior through a conservative trait default.
  Evidence: Criterion `sync_pipeline_apply_spend_heavy_proxy` reported -3.9619% mean change (`p = 0.04`) and `sync_pipeline_apply_spend_heavy_proxy_filter` reported -8.1084% mean change (`p = 0.00`) on the patched run; same-HEAD clean clone means were `73.851ms` / `72.245ms` versus patched `71.987ms` / `71.187ms`. Full fjall/all-index spend-heavy proxy stayed effectively neutral on repeat (`86.122ms` clean vs `86.286ms` patched), so this is recorded only as a narrow no-ZMQ apply-tail compression.

**Measured but rejected in this campaign:**

- [x] Rejected `ApplyScratch` same-block script-capture fusion after same-window `sync_apply_metrics` showed slower filter workloads than the clean baseline.
- [x] Rejected UTXO script-slab bulk reservation after repaired preflight-safe versions produced mixed Criterion results and regressions in same-txid, listener, and concentrated workloads.
- [x] Rejected the empty-mempool write-lock skip as a commit candidate because `sync_apply_metrics` did not produce a defensible fast-path win at printed metric resolution.
- [x] Rejected lowering `PARALLEL_LISTENER_SHARD_THRESHOLD` from 16 to 2 after `utxo_commit/two_shard_noop_listener` regressed by roughly 200% against the current baseline.
- [x] Rejected replacing the sync reverse-scan candidate `Vec` with a ring buffer after `deep_headers_received_scan_128_blocks` regressed by 5.3575% and `many_peers_512` regressed by 10.071%.
- [x] Rejected a serial coinstats event-batch reducer after `coinstats/utxo_commit_listener_two_shard_512` and `8192` showed no significant Criterion movement.
- [x] Rejected a coinstats fanout chunk-capacity hint after `coinstats/utxo_commit_listener_fanout_8192` regressed by 6.5366% and `two_shard_8192` regressed by 3.4566%.
- [x] Rejected a no-listener low-vout bitmap detector for full-record spends after `utxo_commit/interleaved_same_txid_churn` regressed by 14.494% and the no-listener variant regressed by 22.785%.
- [x] Rejected stack-backed coinstats coin-hash scratch buffers after `sync_pipeline_apply_spend_heavy_proxy_filter` regressed by 3.6128% and `deterministic_initial_sync_proxy_production_state_apply_tick_128_blocks` regressed by 2.9976%.
- [x] Rejected ordered full-record UTXO removal before the existing order-independent fallback after the rerun regressed `utxo_commit/spend_fanout_64` by +10.018%, `utxo_commit/spend_fanout_64_noop_listener` by +6.7293%, and `coinstats/utxo_commit_listener_spend_fanout_64` by +11.512%.
- [x] Rejected replacing `UtxoKey::hash()` with direct `as_u64()` after multi-shard UTXO commit shapes regressed despite concentrated single-shard wins.
- [x] Rejected broad `UtxoRecord` helper inlining after `utxo_commit/uniform`, `concentrated`, and `concentrated_noop_listener` regressed significantly.
- [x] Rejected replacing the inbound staged-result `Vec` with a chunk-sized `SmallVec` after received-scan and many-peer scheduler targets regressed despite improving oversized bursts.
- [x] Rejected changing no-spend `ApplyScratch` script capture from `Some(HashMap::new())` to `None` after rerunning `sync_pipeline_apply_spend_heavy_proxy_filter` showed no statistically defensible improvement.
- [x] Rejected storing same-block membership in `ApplyScratch` as `HashSet<Txid>` after the spend-heavy, filter, and production apply-tick sync proxies all stayed within Criterion noise.
- [x] Rejected pre-converting `sync_peer_selection` applied height to `i32` after `many_peers_512` showed no significant movement and the follow-up received-scan/oversized-burst rerun fell back inside Criterion noise.
- [x] Rejected returning drained staged blocks in a `SmallVec` after `production_state_128_blocks` and `production_state_apply_tick_128_blocks` both regressed within Criterion noise, exposing stack/inline-size displacement without a defensible win.
- [x] Rejected skipping disconnected-peer release work when the download window had no pending or inflight state after deterministic sync proxies regressed: deep-headers pure +2.4631%, indexed +3.0131%, received-scan +4.0984%, and many-peers +4.2122%.
- [x] Rejected increasing inserted UTXO event batch inline capacity from 8 to 64 after CoinStats two-shard commit paths regressed: listener two-shard 8192 +12.289%, listener two-shard 512 +7.0375%, and no-listener two-shard 8192 +8.9538%.
- [x] Rejected raising the CoinStats committed-event parallel threshold from 64 to 256 despite two-shard microbench wins, because node spend-heavy sync proxies regressed: unfiltered +14.390% and filter +23.508%.
- [x] Rejected raising the CoinStats committed-event chunk size from 32 to 64 after `coinstats/utxo_commit_listener_two_shard_512` regressed by +22.086% with no significant 8192-listener win.
- [x] Rejected lowering the CoinStats inline event-chunk descriptor buffer from 64 to 16 after `coinstats/utxo_commit_listener_two_shard_8192` regressed by +9.5260% and no-listener two-shard 8192 regressed by +43.149%.
- [x] Rejected enabling txid-run grouping for `coalesces_committed_events()` listeners after the targeted CoinStats listener benches stayed statistically unchanged (`two_shard_8192` -1.9375%, `two_shard_512` +2.1615%, fanout -0.0733%), and node spend-heavy proxies did not produce a material end-to-end win (unfiltered -2.1686% within noise threshold, filter +1.0430% no change).
- [x] Rejected direct serial application of sub-threshold CoinStats committed-event batches after `coinstats/utxo_commit_listener_two_shard_8192` regressed by +27.682% and no-listener `coinstats/utxo_commit_two_shard_8192` regressed by +25.090%; `two_shard_512` and fanout listener workloads showed no significant improvement.
- [x] Rejected binary-search insertion for the already bounded sync request-peer list after scheduler targets showed no significant movement: `many_peers_512` +0.8717%, deep-headers pure +0.3328%, indexed +0.6761%, and received-scan +0.1106%.
- [x] Rejected returning early from `expired_request_entries()` when the expired list is empty after deterministic sync targets regressed: indexed +2.1219% and received-scan +4.6699%; pure and many-peer showed no significant movement, and production-state stayed within the Criterion noise threshold.
- [x] Rejected batching unique coalesced UTXO insert events once per add run after the changed CoinStats guard regressed (`coinstats/utxo_commit_listener_two_shard_512` +4.3772%) and `sync_pipeline_apply_proxy` regressed by +5.5447%; production apply-tick stayed within noise.
- [x] Rejected stack-backed CoinStats coin-hash scratch buffers after the same-window node proxy regressed `spend_heavy_117_all_indexes` from `0.6731ms` average total / `utxo_commit_avg_ms=0.4748` to `0.6768ms` / `0.4962`, despite mixed CoinStats microbench results.
- [x] Rejected reusing CoinStats accounting values from the coin-hash encoder after focused Criterion showed significant regressions in `insert_utxo_8192` (+5.7360%), `listener_insert_coins_8192` (+3.5597%), and `listener_remove_coins_8192` (+3.5349%), while spend-fanout stayed within noise.
- [x] Rejected direct compact-size low-byte emission in CoinStats coin-hash encoding after focused Criterion kept all measured guards inside noise: `coinstats/listener_insert_singleton_batches_64` -1.1982%, `coinstats/utxo_commit_listener_two_shard_512` +0.3778%, and `coinstats/utxo_commit_listener_spend_fanout_64` -1.0663%.
- [x] Rejected streaming CoinStats coin preimages directly into SHA-256 instead of materializing the existing coin byte buffer after listener commit guards regressed: `coinstats/listener_remove_same_txid_coins_8192` +5.2346%, `coinstats/utxo_commit_listener_fanout_8192` +5.3725%, `coinstats/utxo_commit_listener_two_shard_8192` +18.828%, and no-listener `coinstats/utxo_commit_two_shard_8192` +9.2708%; `coinstats/utxo_commit_listener_spend_fanout_64` stayed statistically unchanged.
- [x] Rejected a backend-neutral `WriteBatch::reserve` hook plus txindex post-dedup op-count reservation after all-index production proxies stayed statistically unchanged: `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_128_blocks` +1.2650% (`p = 0.10`) and spend-heavy all-index -2.3249% (`p = 0.20`).
- [x] Rejected using the already-captured predecessor tip for compact-filter previous-header lookup after `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_128_blocks` regressed by +18.140% while `sync_pipeline_apply_spend_heavy_proxy_filter` stayed statistically unchanged at +1.2730% (`p = 0.50`).
- [x] Rejected consecutive txindex funding-row duplicate suppression after the three-run patched median regressed all-index `tx_index_ingest_avg_ms` from the same-window baseline `0.0650` to `0.0695`, and txindex-only spend-heavy also regressed.
- [x] Rejected storing the singleton txindex header row outside `PendingRows` after the repeat proxy regressed `spend_heavy_117_all_indexes` to `0.7167ms` average total with `tx_index_ingest_avg_ms=0.0750`.
- [x] Rejected reserving txindex `PendingRows` from `bitcoin_slices` visitor counts plus a complete verified-txid branch after the combined Criterion guard regressed `sync_pipeline_apply_spend_heavy_proxy_filter` by +4.4285% and left `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_spend_heavy` within noise at +0.5514%.
- [x] Rejected passing `BlockTxPlan`'s no-overlay proof into `ApplyScratch` to skip same-block spend tracking after the intended spend-heavy proxies stayed within noise and deterministic initial-sync apply-tick stayed within the Criterion noise threshold; the unrelated `apply_proxy` win was treated as noise because that path had no spent-input scratch tracking to skip.
- [x] Rejected storing `DownloadWindow` peer-request entries in inline `SmallVec<[PeerRequestEntry; 16]>` after request construction improved (`deep_headers_pure` -6.9547%, `deep_headers_indexed` -2.3811%) but received-scan regressed by +5.8838%, making the net scheduler shape unacceptable.
- [x] Rejected moving exact same-block spent-outpoint planning from `ApplyScratch` into `BlockTxPlan` after `sync_pipeline_apply_proxy` regressed by +7.2032%; spend-heavy and production apply-tick targets stayed within noise.
- [x] Rejected skipping `HashTable::reserve` when shard spare capacity already covers add runs after `utxo_commit/uniform` regressed by +7.6393%, despite wins in `existing` (-4.5789%) and `spend_fanout_64` (-6.2923%).
- [x] Rejected checking `expected_apply_cache` before loading tip snapshots in `drain_cached_expected_blocks` after `production_state_apply_tick_128_blocks` regressed by +4.4620%; production-state, partial-apply, and many-peer targets showed no significant win.
- [x] Rejected one-block inbound staging fast paths after deterministic sync proxies stayed mixed: the helper-factored version improved deep-header scan by -6.0545% and apply-tick by -4.0185% but regressed oversized inbound bursts by +12.405%; the narrowed inline multi-block version improved apply-tick by -2.0777% and oversized bursts by -10.560% but regressed deep-header scan by +9.4876%.
- [x] Rejected single-pass protected-head `BlockStager` eviction after `deep_headers_received_scan_128_blocks` improved by -3.4380% but production-state sync regressed by +4.8993% and production apply-tick regressed by +2.1062%.
- [x] Rejected adding a private contiguous flag to `PeerRequest` after clean request and scheduler proxies regressed: `deep_headers_pure_128_blocks` +10.175%, `deep_headers_indexed_128_blocks` +5.3938%, `deep_headers_received_scan_128_blocks` +3.4194%, `production_state_apply_tick_128_blocks` +3.3182%, `production_state_partial_apply_tick_128_blocks` +8.4149%, and `many_peers_512` +3.5686%.
- [x] Rejected skipping redundant `BlockStager` received-deadline writes after the first run's `production_state_partial_apply_tick_128_blocks` win (-7.8512%) did not reproduce; the repeat showed no significant movement across received-scan, production-state, apply-tick, partial-apply, and many-peer targets.
- [x] Rejected direct serialized-header slicing in `applied_block_record` after `sync_pipeline_apply_proxy` improved by -7.5194% but filter and production sync guards regressed: `sync_pipeline_apply_spend_heavy_proxy_filter` +2.2945%, `production_state_128_blocks` +2.4467%, `production_state_apply_tick_128_blocks` +7.5058%, and `production_state_partial_apply_tick_128_blocks` +2.6409%.
- [x] Rejected caching contiguous remove-run `UtxoKey` derivation in UTXO remove bucket builders after intended spend/full-spend shapes regressed: `utxo_commit/same_txid_full_spend` +10.937%, `same_txid_full_spend_noop_listener` +12.708%, `spend_fanout_64_noop_listener` +9.9217%, and neutral `uniform_noop_listener` +7.1491%.
- [x] Rejected direct spare-capacity backfill in `contiguous_request_entries` after clean request-path guards failed to improve and indexed deep headers regressed: `deep_headers_pure` +0.0643% no change, `deep_headers_indexed` +3.2427%, and `received_scan` +8.2898% within Criterion noise but directionally worse.
- [x] Rejected preallocating per-worker `CoinStatsDelta` scratch buffers after coinstats-local listener wins did not survive node sync guards: patched `sync_pipeline_apply_proxy` was `1.8280ms` versus `1.6535ms` after reverting, and patched `sync_pipeline_apply_spend_heavy_proxy` was `82.357ms` versus clean `79.544ms`.
- [x] Rejected deferring `ApplyScratch` same-block txid `HashSet` allocation behind an eight-transaction linear scan after node apply guards failed to show a durable win: clean `sync_pipeline_apply_proxy` was `1.7140ms` versus patched `1.7665ms`, clean `sync_pipeline_apply_spend_heavy_proxy` was `80.266ms` versus patched `79.475ms` with no significant change, and clean `sync_pipeline_apply_spend_heavy_proxy_filter` was `81.266ms` versus patched `81.285ms` with no significant change.
- [x] Rejected a txindex funding-row helper that returned the scripthash prefix directly from script bytes after same-session fjall apply metrics regressed the intended guards: clean `spend_heavy_117_txindex` was `0.5918ms` average total / `tx_index_ingest_avg_ms=0.0555` versus patched `0.7696ms` / `0.0782`, and clean `spend_heavy_117_all_indexes` was `0.5607ms` / `0.0529` versus patched `0.5726ms` / `0.0516`.
- [x] Rejected a fjall adjacent-column-family keyspace cache inside `FjallStore::write` after node-level fjall all-index apply metrics regressed despite storage-local plausibility: clean `spend_heavy_117_all_indexes` was `0.6745ms` average total / `tx_index_ingest_avg_ms=0.0710` versus patched `0.7050ms` / `0.0792`; clean `spend_heavy_117_txindex` was `0.7176ms` / `0.0777` versus patched `0.5466ms` / `0.0503`, so the mixed target-path result was not accepted.
- [x] Rejected storing outer `SyncPeerSelection` request peers in `SmallVec<[SyncPeer; 1]>` after scheduler guards regressed despite a pure deep-header win: clean `many_peers_512` was `117.45us` versus patched `121.00us` with no significant change, clean `deep_headers_received_scan_128_blocks` was `57.244us` versus patched `60.392us`, clean `production_state_128_blocks` was `3.1862ms` versus patched `3.3716ms`, and clean `oversized_inbound_burst_1024_blocks` was `1.9878ms` versus patched `2.1183ms`.
- [x] Rejected threading the first inbound block hash from apply-head detection into block staging after the intended inbound guard failed to improve durably and several guards moved the wrong way: clean `oversized_inbound_burst_1024_blocks` was `1.9878ms` versus patched `1.9920ms`, clean `deep_headers_received_scan_128_blocks` was `57.244us` versus patched `59.089us`, clean `production_state_apply_tick_128_blocks` was `2.9228ms` versus patched `2.9680ms`, clean `production_state_partial_apply_tick_128_blocks` was `2.0469ms` versus patched `2.0764ms`, and clean `many_peers_512` was `117.45us` versus patched `123.58us`.
- [x] Rejected whole-shard CoinStats event-batch reduction after the broad form regressed `coinstats/utxo_commit_listener_two_shard_8192` by +35.706%, and the narrowed small/medium form regressed the exact node diagnostics: `utxo_spend_heavy_117_listener` rose from `0.4896ms` to `0.6945ms` and `spend_heavy_117_all_indexes` total average rose to `0.8950ms`.
- [x] Rejected replacing the MuHash ChaCha block feed-forward state copy with direct `base_state` indexing after focused Criterion showed no defensible win: same-session baseline vs patched was `muhash_insert_preencoded_8192` `43.559ms` vs `43.938ms`, `muhash_remove_preencoded_8192` `42.177ms` vs `41.675ms`, `listener_remove_coins_8192` `10.805ms` vs `10.654ms`, and `utxo_commit_listener_spend_fanout_64` `1.2671ms` vs `1.2763ms`, all reported as no significant change.
- [x] Rejected applying contiguous inbound chunks during each receive drain after the intended in-order win failed to survive the wider deterministic proxy rerun and the received-scan guard regressed: the exact inbound-only run first improved `deterministic_initial_sync_proxy_in_order_inbound_128_blocks` by -2.5604% to `1.8178ms`, but the all-proxy rerun showed no significant in-order movement at `1.8090ms` while `deep_headers_received_scan_128_blocks` regressed by +8.8774% to `64.334us`.
- [x] Rejected raising the inbound block drain chunk from the byte-estimated chunk size to the full received-block budget after the intended in-order inbound proxy did not improve: `deterministic_initial_sync_proxy_in_order_inbound_128_blocks` moved to `1.8358ms` with a +1.4781% mean change inside the Criterion noise threshold.
- [x] Rejected lazy allocation of the expected-apply hash buffer in `send_getdata_for_pending_blocks` after the initial exact received-scan win did not survive the broad deterministic guard run: the first `deep_headers_received_scan_128_blocks` run improved by -7.7341% to `59.358us`, but the all-proxy rerun regressed pure +6.1261%, indexed +11.875%, received-scan +5.9496%, in-order inbound +7.9465%, production-state +7.8518%, apply-tick +2.8183%, and oversized inbound burst +4.5359%.
- [x] Rejected prevalidated UTXO shard append collection after the intended spend-fanout path did not move (`utxo_commit/spend_fanout_64` -0.0297%, `spend_fanout_64_noop_listener` -2.6748% with p=0.31), while the apparent same-txid wins were outside the patched multi-shard collect path and treated as noise.
- [x] Rejected carrying a precomputed `UtxoKey` inside `BorrowedUtxoAdd` after node-level diagnostics failed to justify the extra borrowed-add state: `sync_apply_metrics` reported `spend_heavy_117_all_indexes` at `0.7129ms` average total with `utxo_commit_avg_ms=0.5382`, directionally worse than the current clean ledger's `0.7115ms` / `0.5114` and without a defensible end-to-end win.
- [x] Rejected reusing CoinStats event scratch inside Rayon fold partitions after the intended allocation reduction regressed `coinstats/utxo_commit_listener_two_shard_8192` by +6.8801% (p=0.00), left `two_shard_512` and `spend_fanout_64` unchanged, and moved the node `spend_heavy_117_all_indexes` diagnostic from the clean `0.5389ms` average total / `utxo_commit_avg_ms=0.4283` to `0.6345ms` / `0.4973`.
- [x] Rejected deriving UTXO bucket-side shape from the already computed active-shard list after the relevant node sync guards failed: `sync_pipeline_apply_spend_heavy_proxy_filter` regressed by +5.6330% (p=0.00), production all-index spend-heavy stayed within noise at -2.5133%, and `sync_apply_metrics` moved all-index spend-heavy from the clean `0.5389ms` average total / `utxo_commit_avg_ms=0.4283` to `0.6867ms` / `0.4979`; the first UTXO microbench wins were not enough to carry the sync regression.
- [x] Rejected skipping txindex pending-row sort/dedup for singleton vectors after the mixed sync guard failed the all-index production shape: `sync_pipeline_apply_spend_heavy_proxy_filter` improved by -10.518% (p=0.00), but `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_128_blocks` regressed by +17.243% (p=0.00), while all-index spend-heavy stayed within noise and the diagnostic did not show a stable txindex-stage win.
- [x] Rejected caching the last compact-filter header in `ApplyHandles` after the all-index spend-heavy sync guard regressed despite a smaller all-index win: `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_128_blocks` improved by -8.9548% (p=0.00), but `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_spend_heavy` regressed by +8.8092% (p=0.00); `sync_pipeline_apply_spend_heavy_proxy_filter` showed no significant movement at +2.7060%.
- [x] Rejected deferring `DownloadWindow` pending-deadline refreshes across scoped receive/apply batches after the cleaned-up private batch API failed the clean all-index comparison: clean `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_128_blocks` was `6.7269ms` versus patched `7.2463ms`, and clean `deterministic_initial_sync_proxy_production_state_fjall_all_indexes_spend_heavy` was `88.319ms` versus patched `89.526ms`. The earlier unscoped-token variant showed benchmark wins but was rejected by review for growing caller obligations around deadline-refresh completion.
- [x] Rejected skipping `BlockLocalUtxoMetaView` construction for BIP68 checks when `BlockTxPlan` proved no local overlay was needed after the existing sync diagnostic workloads produced no measurable BIP68-stage signal (`bip68_avg_ms=0.0000` clean and patched because the proxy transactions use disabled sequences) and the all-index spend-heavy diagnostic regressed from clean `total_avg_ms=0.5484` to patched `0.6355`; the narrow BIP68 unit tests passed, but the change did not improve the initial-sync proxy surface.
- [x] Rejected a `NoOpZmqPublisher` notification-interest hook after the apply proxy guard regressed: `sync_pipeline_apply_proxy` reported `time: [1.8037 ms 1.8268 ms 1.8490 ms]` with `change: [+1.6086% +3.4185% +5.2951%]` and `p = 0.00`, despite focused ZMQ publisher and rawtx-order tests passing.
- [x] Rejected reusing a caller-owned staged-block result `Vec` across inbound receive chunks after its primary inbound guard regressed: `deterministic_initial_sync_proxy_in_order_inbound_128_blocks` reported `time: [1.8035 ms 1.8158 ms 1.8280 ms]` with `change: [+1.2727% +2.4033% +3.4636%]` and `p = 0.00`, despite focused inbound-drain and sync-smoke tests passing.
- [x] Rejected narrowing `advance_expected_apply_cache`'s mutex hold by loading tip snapshots before the cache lock after the primary cached-apply guard regressed: `deterministic_initial_sync_proxy_production_state_apply_tick_128_blocks` reported `time: [3.0965 ms 3.1492 ms 3.2038 ms]` with `change: [+6.2573% +8.0693% +9.9571%]` and `p = 0.00`, despite deterministic proxy, mid-batch restore, and sync-smoke tests passing.
- [x] Rejected removing the duplicate per-add script-length check from listener shard preflight after the guard shape split: `utxo_commit/uniform_noop_listener` improved by -28.608% (`time: [4.3367 ms 4.4996 ms 4.7211 ms]`, `p = 0.00`), but `utxo_commit/concentrated_noop_listener` regressed by +31.002% (`time: [4.5171 ms 4.5918 ms 4.6680 ms]`, `p = 0.00`), despite invalid-add atomicity and full `commit_roundtrip` tests passing.
- [x] Rejected pre-sizing block serialization with `Block::total_size()` before `Bytes` conversion after the extra size traversal failed the apply diagnostic: targeted byte-equivalence and body-store failure-order tests passed, but `sync_apply_metrics` moved `spend_heavy_117_all_indexes` to `0.6332ms` average total with `block_body_persist_avg_ms=0.0050`, worse than the current accepted storage-copy run at `0.5811ms` / `0.0047`.
- [x] Rejected an owned `Bytes` fast path for compact-filter row writes after filter/all-index diagnostics regressed: `sync_apply_metrics` moved `spend_heavy_117_filter` to `0.5878ms` average total with `filter_index_avg_ms=0.0074` and `spend_heavy_117_all_indexes` to `0.7599ms` / `filter_index_avg_ms=0.0111`, despite filter-index, BIP158 vector, GCS property, and apply filter-row tests passing.
- [x] Rejected copying expected sync apply hashes from a public active-height range helper after the clean-clone guard showed no material main-target win and a partial-apply regression: `deterministic_initial_sync_proxy_production_state_apply_tick_128_blocks` was `2.9602ms` clean versus `2.9559ms` patched, while `deterministic_initial_sync_proxy_production_state_partial_apply_tick_128_blocks` regressed from `2.0849ms` clean to `2.1944ms` patched.

**Still pending:**

- [ ] Prove G14 initial block sync throughput is faster than Bitcoin Core on identical mainnet IBD hardware and configuration.
- [ ] Prove all G14 budgets, not just proxy workloads: UTXO commit p95 <= 50 ms per 4 MiB block, Electrum history p95 <= 30 ms over the required sample, and RSS <= 16 GiB at mainnet tip with fjall default plus indexes.
- [ ] Run and preserve full gate evidence for G1-G14 across two consecutive `main` CI runs before declaring bitcoin-rs shippable.
- [ ] Keep Task 5, Task 18, and Task 20 below pending as broad roadmap tasks until their complete step lists and gate evidence are satisfied.

---

## Tasks

### Task 0: Workspace bootstrap

**Files:**
- Create: `bitcoin-rs/Cargo.toml`
- Create: `bitcoin-rs/Cargo.lock` (committed after first `cargo build`)
- Create: `bitcoin-rs/rust-toolchain.toml`
- Create: `bitcoin-rs/clippy.toml`
- Create: `bitcoin-rs/deny.toml`
- Create: `bitcoin-rs/README.md`
- Create: `bitcoin-rs/LICENSE`
- Create: `bitcoin-rs/PLAN.md` (mirror of this file)
- Create: `bitcoin-rs/.github/workflows/ci.yml`
- Create: `bitcoin-rs/.gitignore`
- Create: empty `crates/<name>/Cargo.toml` + `crates/<name>/src/lib.rs` for all 18 crates
- Create: `bitcoin-rs/bin/bitcoin-rs/Cargo.toml` + `bitcoin-rs/bin/bitcoin-rs/src/main.rs`

- [ ] **Step 1: Initialize git + workspace skeleton**

```bash
mkdir -p ~/dev/bitcoin-rs/bitcoin-rs && cd $_
git init -b main
mkdir -p crates/{primitives,consensus,script,storage,utxo,utreexo,chain,index,filters,coinstats,pruning,mempool,p2p,wallet,mining,rpc,electrum,node}/src
mkdir -p bin/bitcoin-rs/src
mkdir -p benches .github/workflows
```

- [ ] **Step 2: Write `Cargo.toml` workspace root**

```toml
[workspace]
resolver = "3"
members = [
    "crates/primitives", "crates/consensus", "crates/script", "crates/storage",
    "crates/utxo", "crates/utreexo", "crates/chain", "crates/index",
    "crates/filters", "crates/coinstats", "crates/pruning", "crates/mempool",
    "crates/p2p", "crates/wallet", "crates/mining", "crates/rpc",
    "crates/electrum", "crates/node",
    "bin/bitcoin-rs",
]

[workspace.package]
edition = "2024"
rust-version = "1.95.0"
license = "MIT OR Apache-2.0"
repository = "https://github.com/<owner>/bitcoin-rs"
version = "0.1.0"

[workspace.dependencies]
# … full dep table from above …

[workspace.lints.rust]
unsafe_op_in_unsafe_fn = "deny"
missing_docs = "warn"
unreachable_pub = "warn"

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
undocumented_unsafe_blocks = "deny"
as_conversions = "deny"
cast_lossless = "deny"
unwrap_used = "deny"
expect_used = "warn"
dbg_macro = "deny"
todo = "deny"
unimplemented = "deny"
mod_module_files = "deny"

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
debug = "line-tables-only"
strip = "symbols"

[profile.bench]
opt-level = 3
lto = "fat"
codegen-units = 1
debug = "line-tables-only"

[profile.dev]
opt-level = 1
debug = "limited"
```

- [ ] **Step 3: `rust-toolchain.toml`, `clippy.toml`, `deny.toml`, `.gitignore`** — literal content as defined above.

- [ ] **Step 4: Each crate's `Cargo.toml`** — minimal:

```toml
[package]
name = "bitcoin-rs-<crate>"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
version.workspace = true

[lints]
workspace = true

[dependencies]
# crate-specific; declared with .workspace = true
```

- [ ] **Step 5: Each crate's `src/lib.rs`** — minimal:

```rust
#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]
```

(No `README.md` yet — create empty stub per crate to satisfy the include; replaced with real docs in the per-task work.)

- [ ] **Step 6: Mirror this plan to `bitcoin-rs/PLAN.md`** — verbatim copy.

- [ ] **Step 7: `cargo build --workspace`** verify the skeleton compiles.

- [ ] **Step 8: `cargo +1.95.0 clippy -p bitcoin-rs --all-targets --no-default-features --features "$FEATURES" -- -D warnings`** — fix any skeleton-level violations.

- [ ] **Step 9: Commit.**

```bash
git add .
git commit -m "chore: workspace bootstrap" -m "Op: extend"
```

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
- Create: `crates/consensus/src/{lib,kernel,rust_path,verify_tx,verify_block,connect_block,bip9,bip30,bip34,bip65,bip66,bip68,bip112,bip113,bip141,bip143,bip341,bip342}.rs`
- Test: `crates/consensus/tests/{kernel_parity,vectors}.rs`
- Vendor: `crates/consensus/tests/vectors/{tx_valid,tx_invalid,script_tests,sighash}.json` (from Bitcoin Core `src/test/data/`)

- [ ] **Step 1: Vendor consensus vectors.** Copy from `~/dev/bitcoin-rs/bitcoin/src/test/data/{tx_valid,tx_invalid,script_tests,sighash}.json`. Commit verbatim with original SHA-256 documented in the commit body.

- [ ] **Step 2: `crates/consensus/src/kernel.rs`** — thin wrapper around `bitcoinkernel::*`: `KernelContext::new(network)`, `KernelContext::verify_tx(&Tx, &UtxoView, height, flags)`, `KernelContext::connect_block(&Block, &PrevTip)`. Errors map to `thiserror`-tagged `ConsensusError`.

- [ ] **Step 3: `crates/consensus/src/rust_path.rs`** — `RustValidator { /* sigops counter, BIP9 state, BIP30 dupe-tx table, etc */ }`. Mirrors kernel's contract. Internally uses `crates/script` for script verification, `crates/primitives` for sighash, `rustreexo` for utreexo-mode proof verification.

- [ ] **Step 4: `connect_block`** — runs *both* kernel and Rust path. On disagreement: log structured error with both error states, the offending block hash, height, and the disagreeing assertion; *return kernel's verdict*. CI hard-fails on any disagreement during the first 100 000 blocks of mainnet IBD.

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
- Bench: `benches/kvstore_backends.rs`

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

- [ ] **Step 2: `ColumnFamily` enum** — exactly electrs's 5 CFs: `TxConfirmed`, `TxMempool`, `BlockHeaders`, `Funding`, `Spending`. Plus `Filters` (BIP157/158), `FilterHeaders`, `Coinstats`, `BlockTree`, `UtxoMeta` (snapshot ptrs).

- [ ] **Step 3: RocksDB impl.** Mirror `electrs/src/db.rs` block-based options exactly (4 MiB blocks, lz4 compression, 256 MiB block-cache, bloom 10 bits/key, mt static). All CFs pre-created at open.

- [ ] **Step 4: MDBX impl (feature `mdbx`).** Via `signet-libmdbx >=0.8` (init4tech/mdbx). One `Environment` per database, one `Database` (LMDB-style sub-db) per CF. Use `EnvironmentBuilder::set_max_dbs(N)` for our CF count; `set_geometry` with lower/upper bound sized for a tip-resident UTXO + indexes (e.g. lower 1 GiB, upper 1 TiB, growth step 1 GiB). All writes go through a single `RwTransaction` per `KvStore::write` call — MDBX's single-writer model maps naturally to our batched commit shape. **Critical:** Reth + Erigon prove this works at Ethereum-mainnet scale (∼1.7 TiB live, billions of state entries); UTXO + indexes are well within the envelope. Document the wait-free reader semantics — Electrum queries do not block UTXO commits because MDBX readers operate on consistent MVCC snapshots without coordinating with the writer.

- [ ] **Step 5: fjall impl (feature `fjall`).** One `Keyspace`, one `Partition` per CF. Same write-batch semantics. Document the (real) flush-on-fsync differences in inline comments.

- [ ] **Step 6: redb impl (feature `redb`).** One `TableDefinition` per CF. Write-batches map to a single `WriteTransaction`.

- [ ] **Step 7: `backend_equivalence.rs` test** — for each backend: insert 10 000 rows across 5 CFs, read them back, prefix-iterate, delete-range; assert byte-identical results across backends.

- [ ] **Step 8: `benches/kvstore_backends.rs`** — criterion benchmark: write 1M sequential keys, write 1M random keys, point-get 1M keys, prefix-iter 100K-key prefix, 16-thread mixed-read-write workload. Report saved to `target/criterion/kvstore_backends/report/index.html` and an aggregate summary appended to `target/bench-report.md`.

- [ ] **Step 9: Commit.**

```bash
git commit -am "feat(storage): KvStore trait + fjall default + rocksdb + mdbx + redb features" -m "Op: extend"
```

---

### Task 5: `crates/utxo` — 256-shard HashTable over self-cell-pinned Bump

**Files:**
- Create: `crates/utxo/src/{lib,key,record,shard,set,snapshot,defrag}.rs`
- Test: `crates/utxo/tests/{commit_roundtrip,reorg,snapshot_roundtrip,defrag_invariants}.rs`
- Bench: `benches/utxo_commit.rs`

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

- [ ] **Step 13: `benches/utxo_commit.rs`** — criterion: commit synthetic 4 MiB blocks at 10 k input + 10 k output density; report p50 / p95 / p99 + entries-per-shard distribution.

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

### Task 9: `crates/filters` — BIP157 cfheaders + BIP158 GCS encoding

**Files:**
- Create: `crates/filters/src/{lib,gcs,cfheaders,filter_index}.rs`
- Test: `crates/filters/tests/bip158_vectors.rs`

- [ ] **Step 1: GCS-encoded filter (BIP158)** — `P=19`, `M=784931`. Golomb-Rice coding; SipHash-1-3 key derivation from block hash.

- [ ] **Step 2: `FilterHeader { prev_header, filter_hash } → header_hash`** chain per BIP157.

- [ ] **Step 3: Filter index** — `Filters` CF + `FilterHeaders` CF (Task 4). One row per block: key = `Hash256`, value = filter bytes.

- [ ] **Step 4: BIP158 reference vectors** — vendor `bitcoin/src/test/data/blockfilters.json`; runner asserts byte-identical filter + filter header.

- [ ] **Step 5: Commit.**

```bash
git commit -am "feat(filters): BIP157/158 cfheaders + GCS filter index" -m "Op: extend"
```

---

### Task 10: `crates/coinstats` — running muhash3072 for O(1) gettxoutsetinfo

**Files:**
- Create: `crates/coinstats/src/{lib,muhash3072}.rs`
- Test: `crates/coinstats/tests/parity_against_core.rs`

- [ ] **Step 1: `MuHash3072`** — 3072-bit multiplicative hash, group elements over residues mod `2^3072 - r`. Port from `bitcoin/src/crypto/muhash.cpp` exactly (constant-time mul + inv).

- [ ] **Step 2: `CoinStats { muhash: MuHash3072, height: u32, total_amount: u64, bogo_size: u64, …}`** updated on each `commit_block`.

- [ ] **Step 3: Persist `CoinStats` to `Coinstats` CF** keyed by `height`.

- [ ] **Step 4: Parity test** — run `bitcoind --txindex` to height 100 000; dump its `gettxoutsetinfo --hash-type=muhash`; compare against ours at the same height.

- [ ] **Step 5: Commit.**

```bash
git commit -am "feat(coinstats): muhash3072 running + O(1) gettxoutsetinfo" -m "Op: extend"
```

---

### Task 11: `crates/pruning` — block + undo pruner; utreexo-only mode

**Files:**
- Create: `crates/pruning/src/{lib,policy,block_pruner,undo_pruner,utreexo_only}.rs`
- Test: `crates/pruning/tests/{prune_then_reorg,utreexo_no_blocks}.rs`

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

- [ ] **Step 6: Inbound dispatch** — `version`, `verack`, `ping`/`pong`, `inv`, `getheaders`, `headers`, `getblocks`, `block`, `tx`, `getdata`, `notfound`, `addr`/`addrv2`, `getaddr`, `mempool`, `filterload`/`filteradd`/`filterclear` (BIP37 — accept but ignore; we serve filters via BIP157 instead), `cfheaders`/`cfilter`/`getcfheaders`/`getcfilter`/`getcfcheckpt` (BIP157).

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
- `getblockfilter` (BIP157)
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

- [ ] **Step 1: `Config`** — TOML + CLI (clap) + env (`BITCOIN_RS_*`). `bitcoin.conf` compatibility layer that parses Core's `bitcoin.conf` format into our `Config` for the overlapping option set (`-prune`, `-rpcuser`, `-rpcpassword`, `-server`, `-listen`, `-txindex`, `-blockfilterindex`, `-dbcache`, …). Conflicts resolved in order: CLI > env > TOML > bitcoin.conf > defaults.

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

### Task 20: Verification gates G1–G14 — flat acceptance suite

**Files:**
- Create: `tests/gates/{g1_headers_parity,g2_utxo_root_parity,g3_kernel_parity,g4_consensus_vectors,g5_electrum_parity,g6_snapshot_roundtrip,g7_backend_equivalence,g8_utreexo_parity,g9_wallet_psbt_roundtrip,g10_reorg_deep,g11_crash_recovery,g12_graceful_shutdown,g13_lints,g14_perf_budgets}.rs`
- CI: `.github/workflows/gates.yml`

Each gate is a `#[test]` (gate G14 is a separate criterion run gated by `--features perf-gates`). CI runs all of them. Plan is "done" when all 14 gates are green for two consecutive CI runs on `main`.

- [ ] **Step 1–14:** Each gate test as defined in *Verification Gates* above. Each in its own file, each callable independently via `cargo test -p bitcoin-rs --test g<N>_*`.

- [ ] **Step 15: CI matrix** — runs gates against `--no-default-features --features rocksdb`, `--no-default-features --features fjall`, `--no-default-features --features redb` (G7).

- [ ] **Step 16: Commit.**

```bash
git commit -am "test(gates): verification gates G1-G14" -m "Op: extend"
```

---

## Ultrareview Log (oracles + web research applied)

Recorded so subsequent reviewers can see what changed during the original plan's external review and why. Findings from the adversarial critic pass (`task: critic`) and four parallel web-research probes were folded back into the plan above.

### CRITICAL — fixed

1. **Self-referential `ShardInner` was Undefined Behavior on move.** The original sketch stored `Bump` + `HashTable<ArenaRef<'static>>` in one struct via `mem::transmute` to erase the lifetime. `[Shard; 256]` array initialization and `CachePadded` wrapping both move the struct after pointers are taken, dangling them. **Fix:** wrapped in `self_cell!` with `Box<bumpalo::Bump>` as the owner so the arena address is pin-stable; added `self_cell >=1.2` to workspace deps.
2. **Porting consensus from gocoin was a chain-split risk.** Original plan implemented PoW, sigops, merkle, script verification independently. **Fix:** `bitcoinkernel = ">=0.2"` is now a non-optional dependency; our Rust validator runs alongside and panics on any kernel disagreement. A `pure-rust-validation` feature is deferred until 12 months of clean mainnet parity.

### HIGH — fixed

3. **`parking_lot::Mutex` per shard would have stalled Electrum readers.** Electrum's `scripthash.get_history` does random-access reads against the UTXO map concurrent with consensus commits; under a `Mutex` shard, a block-commit holds every reader off for the entire commit window. **Fix:** restored `parking_lot::RwLock<ShardCell>`; block commits batch one write-lock per shard per block (not per UTXO op), so writer starvation is still bounded.
4. **Gocoin `UTXO.db` interop claim was a serialization minefield.** Go and Rust integer encoding, struct padding, varint shapes, and endianness assumptions do not match for free. **Fix:** snapshot uses our **own** format (`zerocopy`-backed, explicit LE, magic + version + muhash trailer); the gocoin import goal is explicitly out of scope. The ABORT / HURRY-UP channel pattern from gocoin is still ported because it is format-agnostic.

### MEDIUM — fixed

5. **Mainnet-diff verification did not exercise adversarial consensus boundaries.** Mainnet never replays CVE-2018-17144 (duplicate inputs), zero-value outputs, or many script edge cases. **Fix:** G4 vendors Core's `tx_valid.json`, `tx_invalid.json`, `script_tests.json`, `sighash.json`; G3 is the per-block kernel parity gate during IBD.

### Dependency spec errors corrected via web research

| Original claim | Actual fact | Source |
| --- | --- | --- |
| `sha2 >=0.10` with `features = ["asm"]` would always work | `sha2 0.11` **removed** the `asm` cargo feature; assembly is now picked automatically via stable inline asm | https://github.com/RustCrypto/hashes/blob/master/sha2/CHANGELOG.md |
| `bitcoin_hashes` feature is `sha2-asm` | Current workspace uses `bitcoin_hashes >=0.14.100, <0.15` with `std`; no `asm` feature is exposed in the active manifest line | Cargo.toml |
| `hashbrown` raw-entry feature is needed for `HashTable` | `HashTable` is the stable replacement for the experimental `raw` API; raw API is being phased out | https://docs.rs/crate/hashbrown/latest/source/CHANGELOG.md |
| `rustreexo >=0.3` exposes `Pollard`/`MemForest` | Current stable is `0.7.x`; older 0.3 line predates the three-accumulator public API | https://docs.rs/rustreexo |

### Dependency audit 2026-05-19 — additions, swaps, version floor bumps

Triggered by user feedback: *"RocksDB is also previous generation. Use better ones. I'll try them all first and put in what benches well."* All crate decisions below were re-verified against crates.io / GitHub release pages on 2026-05-19. The full per-area audit lives in `agent://5-ModernKvAudit` + sibling agents and is summarized here.

**Storage backend matrix expanded from 3 → 4.**

| Backend | Floor | Production users | Why added/kept | Source |
| --- | --- | --- | --- | --- |
| `rust-rocksdb` | `>=0.49` | Bitcoin Core, electrs, many indexers | Battle-tested explicit backend; zaidoon1 fork actively maintained (0.49.1 2026-05-18) | https://github.com/zaidoon1/rust-rocksdb |
| `signet-libmdbx` | `>=0.8` | **Reth (Paradigm's Rust Ethereum execution client), Erigon, Silkworm, Akula** — all use libmdbx as primary blockchain storage at mainnet scale (∼1.7 TiB) | Memory-mapped CoW B+tree, wait-free readers, no WAL, deterministic crash recovery | https://crates.io/crates/signet-libmdbx · https://github.com/init4tech/mdbx · https://reth.rs/ |
| `fjall` | `>=3.1` | Growing embedded use (axum/actix services) | Default backend; pure-Rust LSM with native column families + `WriteBatch` + serializable txns | https://github.com/fjall-rs/fjall |
| `redb` | `>=4.1` | electrs and other indexers | Pure-Rust single-file CoW B+tree with typed `TableDefinition` | https://github.com/cberner/redb |

**Rejected storage contenders (with primary-source rationale):**
- **Speedb (RocksDB-compatible fork)** — promising C++ perf (Paired Bloom Filter, 30–50 % write throughput claims per docs.speedb.io) but the Rust binding (`rust-speedb`) has had no commits in >2 years; reject until a maintained binding exists.
- **sled 1.0.0-alpha** — community consensus is "beta forever"; storage rewrite has moved to `komora/marble`; do not use.
- **canopydb / persy / surrealkv / marble / sanakirja** — all too early or too niche; no blockchain-scale production proof.
- **heed (LMDB wrapper)** — viable for read-heavy secondary indexes but adds a C dependency and single-writer limitation already covered by MDBX; not a fourth backend.

**Major dep-stack version floor bumps (every entry's latest stable on crates.io as of 2026-05-19):**

| Crate | Was | Now | Why |
| --- | --- | --- | --- |
| `mimalloc` | `>=0.1` | `>=0.1.50` | 0.1.50 (2026-04-22) latest |
| `hashbrown` | `>=0.15` | `>=0.17` | 0.17.1 (2026-05-09) latest; MSRV 1.95 matches; `HashTable` is the stable raw-insertion API |
| `bumpalo` | `>=3.16` | `>=3.20` | 3.20.2 (2026-02-19) latest |
| `self_cell` | `>=1.2` | `>=1.2.2` | 1.2.2 (2025-12-30) latest |
| `parking_lot` | `>=0.12` | `>=0.13` | 0.13.0 (2026-03) latest |
| `arc_swap` | `>=1.7` | `>=1.9` | 1.9.1 (2026-04-04) latest |
| `crossbeam-channel` | `>=0.5` | `>=0.5.15` | 0.5.15 (2025-04-08) latest |
| `rayon` | `>=1.10` | `>=1.12` | 1.12.0 (2026-04-14) latest |
| `foldhash` | `>=0.1` | `>=0.2` | 0.2.0 (2025-08-23) latest |
| `tinyvec` | `>=1.8` | `>=1.11` | 1.11.0 (2026-03-14) latest |
| `smallvec` | `>=1.13` | `>=1.15` | 1.15.1 (2025-06-06) latest |
| `compact_str` | `>=0.8` | `>=0.9` | 0.9.0 (2025-02-25) latest |
| `bytemuck` | `>=1.18` | `>=1.25` | 1.25.0 (2026-01-31) latest |
| `zerocopy` | `>=0.7` | `>=0.8` | 0.8 is a trait redesign (`TryFromBytes`/`IntoBytes`/`KnownLayout`); migrate now |
| `secp256k1` | `>=0.30` | `>=0.31` | 0.31 stable (batch Schnorr verify); 0.32 is still beta |
| `bitcoinkernel` | `>=0.1` | `>=0.2, <0.3` | Corrected to match the active workspace manifest and kernel parity gate. |
| `rustreexo` | `>=0.7` | `>=0.5` | Corrected: actual latest stable is 0.5.0; 0.7 does not exist on crates.io |
| `miniscript` | `>=12` | `>=13` | 13.0.0 (2025-10-28) latest stable |
| `thiserror` | `>=1.0` | `>=2.0` | 2.0.18 (2026-01-18) latest |
| `clap` | `>=4.5` | `>=4.6` | 4.6.1 (2026-04-15) latest |
| `signal-hook` | `>=0.3` | `>=0.4` | 0.4.4 (2026-04-04) latest |
| `proptest` | `>=1.5` | `>=1.11` | 1.11.0 (2026-03-24) latest |
| `criterion` | `>=0.5` | `>=0.8` | 0.8.2 (2026-02-04) latest |
| `fjall` | `>=2.4` | `>=3.1` | 3.1.4 (2026-04-14) latest — disk-format change vs 2.x |
| `redb` | `>=2.2` | `>=4.1` | 4.1.0 (2026-04-19) latest |
| `rust-rocksdb` | `>=0.36` | `>=0.49` | 0.49.1 (2026-05-18) latest |
| `metrics-exporter-prometheus` | `>=0.16` | `>=0.18` | 0.18.3 (2026-04-30) latest |
| `tracing-subscriber` | `>=0.3` | `>=0.3.23` | 0.3.23 (2026-03-13) latest |
| `metrics` | `>=0.24` | `>=0.24.6` | 0.24.6 (2026-05-13) latest |

**New crates added to the stack:**

| Crate | Floor | Role | Source |
| --- | --- | --- | --- |
| `signet-libmdbx` | `>=0.8` | 4th storage backend (MDBX) | crates.io/signet-libmdbx |
| `bitcoin_slices` | `>=0.11` | Zero-alloc block visitor used by `crates/index` (the real crate name behind electrs's `bsl::` namespace) | crates.io/bitcoin_slices |
| `bdk_coin_select` | `>=0.4` | BnB + knapsack + waste-metric coin selection for `crates/wallet` | crates.io/bdk_coin_select |
| `sonic-rs` | `>=0.5` | SIMD JSON parser (4-5× `serde_json` on RPC payloads) for `crates/rpc` + `crates/electrum` hot path | crates.io/sonic-rs · github.com/cloudwego/sonic-rs |
| `rustls` + `rustls-pki-types` | `>=0.23` / `>=1.14` | Electrum TLS listener; was implicit, now explicit | crates.io/rustls |
| `proptest-derive` | `>=0.8` | `#[derive(Arbitrary)]` for property tests | crates.io/proptest-derive |
| `portable-atomic` | `>=1.13` | Optional 128-bit atomics for future lock-free counters | crates.io/portable-atomic |
| `lz4_flex` | `>=0.11` | Pure-Rust LZ4 for snapshot + custom-format compression | crates.io/lz4_flex |
| `rapidhash` | `>=4.1` | Dev-dep only; future G14 comparison candidate | crates.io/rapidhash |
| `payjoin` | `>=1.0` | Optional feature `payjoin` (BIP78/77); default off | crates.io/payjoin |

**Rejected crate-stack alternatives (kept the current choice with rationale):**
- **Channels:** `flume` and `kanal` are fast but lack crossbeam-channel's `Select` macro — non-negotiable for the single-threaded event loop.
- **Allocators:** `snmalloc-rs` and `tikv-jemallocator` remain unadjudicated alternates; they are not current workspace dependencies and require a dedicated G14 alloc-comparison follow-up before any default change.
- **Thread pool:** `chili` is faster on micro-tasks but `rayon`'s work-stealing maturity wins for block-parallel script verify.
- **Self-ref pin:** `ouroboros` is heavier and exposes Pin; `self_cell`'s proc-macro-free shape is optimal.
- **Coin selection:** porting Core's C++ `coinselection.cpp` was the original plan; `bdk_coin_select` supersedes it (audited, BIP-aligned, Rust-native).
- **JSON-RPC framework:** every modern framework (`jsonrpsee`, `tower-jsonrpc`) requires tokio; `jsonrpc-core` is deprecated. Hand-rolled minimal sync HTTP/1.1 is the only honest path.
- **Compact string:** `smartstring` is abandoned (2022); `flexstr` is interesting but `compact_str` is the established choice.
- **Stale crates rejected outright:** `arrayvec` (frozen since 2024-08), `base58` (frozen 2021), `usync` (dead 2022), `typed-arena` (2023), `rpmalloc-rs` (abandoned), `Speedb rust binding` (2 years stale).

**Architectural impact:** Goal, Architecture, Workspace Layout, Tech Stack table, Verification Gate G7, Task 4 (storage), Task 8 (index), Task 14 (wallet), Task 16 (rpc), Task 17 (electrum) all updated above to reflect this audit.

### Findings deliberately NOT actioned (with rationale)

- Critic flagged scope creep around `crates/{utreexo,rpc,electrum,mempool}` as MVP-bloat. Plan keeps them as required tasks because the **stated user goal** is "natively integrate UTXO based on electrs", which requires the Electrum surface and a mempool to ship; the user later explicitly extended scope to include wallet + mining + pruning, confirming the non-MVP direction.
- Critic flagged dependency-velocity risk on `bitcoin >=0.32` and `rust-rocksdb >=0.36`. Floors are kept loose by design — the workspace's `cargo update` + lockfile is the actual pin; floors only protect against trivial regressions.
- Critic suggested deferring fjall/redb behind features as "noise". User explicitly chose all three benchmarked. Backends remain feature-gated but all three ship and are gated by G7.

---

## Execution Handoff

**REQUIRED SUB-SKILL:** `superpowers:subagent-driven-development` — fresh subagent per task, spec-reviewer subagent between tasks to audit TDD discipline and reject stubs.

**Ordering rule:** Tasks 0 → 20 in sequence. No parallel implementation of dependent tasks. The spec-reviewer must sign off on each task before the next one starts. Verification gates G1–G14 (Task 20) gate the project as "done" — bitcoin-rs is not shippable until every gate is green for two consecutive CI runs on `main`.

**Workspace setup:** `superpowers:using-git-worktrees` should have created an isolated workspace before this plan executes. The plan's `bitcoin-rs/` subdirectory lives inside that worktree; reference repos (`gocoin/`, `electrs/`, `utreexod/`, `bitcoin/`, `btcd/`) remain readable from the cwd parent.

**Done definition:** All 21 tasks committed, all 14 verification gates green twice on `main`, `cargo +1.95.0 clippy -p bitcoin-rs --all-targets --no-default-features --features "$FEATURES" -- -D warnings` clean, `cargo deny check` clean, `cargo +1.95.0 fmt --check` clean, `target/release/bitcoin-rs --version` prints `0.1.0`, IBD to mainnet tip completes with G2 + G3 + G14 all reporting green.
