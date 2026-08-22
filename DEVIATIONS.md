# Implementation Deviations from PLAN.md

`PLAN.md` is the spec. This file records places where implementation reality
forced corrections, with sources.

Every entry below was verified against the crates.io registry via
`cargo info <crate>` and `cargo info <crate>@<version>` on **2026-05-19** under
Rust toolchain `1.85.0` (the MSRV declared by `PLAN.md`).

## 0. Workspace bootstrap (Task 0) — dependency audit corrections

The `PLAN.md` "Dependency audit 2026-05-19" section overstated several version
numbers. The corrections below preserve the audit's intent (latest stable line
compatible with MSRV 1.85) while reflecting the actual registry state.

### Crate-name fix

| In `PLAN.md` | Reality on crates.io | Why |
|---|---|---|
| `arc_swap` | `arc-swap` | The crates.io registry name uses a hyphen. Rust `use arc_swap::…` still works (cargo maps hyphen→underscore in identifiers). |

### Version-floor fixes (`PLAN.md` floor > latest stable)

| Crate | `PLAN.md` floor | Latest stable | Floor we use |
|---|---|---|---|
| `parking_lot` | `>=0.13` | `0.12.5` | `>=0.12.5, <0.13` |
| `rust-rocksdb` | `>=0.49` | `0.44.2` | `>=0.44, <0.45` |
| `fjall` | `>=3.1` | `2.11.2` | `>=2.11, <3.0` |
| `redb` | `>=4.1` | `2.6.3` | `>=2.6, <3.0` |
| `criterion` | `>=0.8` | `0.7.0` (MSRV-bound) | `>=0.7, <0.8` |
| `bitcoinkernel` | `>=0.1` | `0.2.0` | `>=0.2, <0.3` |

`criterion 0.8.2` exists but requires Rust 1.86; under our MSRV 1.85 the
registry resolves to `0.7.0`.

### Feature-name fixes

| Crate | `PLAN.md` features | Reality on the floor we pin | Action |
|---|---|---|---|
| `bitcoin_hashes 0.14` | `["asm"]` | 0.14 has no `asm` feature (only `alloc`, `std`, `bitcoin-io`, `io`, `schemars`, `serde`, `small-hash`). The asm path arrives transitively via `sha2 = ["asm"]`. | Drop `"asm"`; keep `"std"`. |
| `secp256k1 0.31` | `["rand-std", …]` | The feature is `rand`, not `rand-std`. | Rename. |
| `rustls 0.23` | `["std", "ring", "tls12"]` | Same features exist; we also enable `"logging"` to keep failure surfaces traceable. | Add `"logging"`. |
| `payjoin` (both 0.23 and 1.0-rc.2) | `["send", "receive"]` | Neither version exposes those names. 0.23 uses `["v2"]`; 1.0-rc.2 uses `["v1", "v2"]`. | Drop from `[workspace.dependencies]`; **Task 14** redeclares it with feature names verified against the version current then. |

### Forward-line crates kept on the older stable line

| Crate | Latest on crates.io | We pin | Why |
|---|---|---|---|
| `sha2` | `0.11.0` | `>=0.10.9, <0.11` | `0.11` removed the `asm` cargo feature; PLAN.md audit explicitly stays on `0.10`. |
| `bitcoin` | `0.33.0-beta` | `>=0.32.9, <0.33` | `0.33` is still beta; PLAN.md stays on stable `0.32.x`. |
| `bitcoin_hashes` | `0.20.0` | `>=0.14.1, <0.15` | Aligned with `bitcoin 0.32` transitive pin. |
| `secp256k1` | `0.32.0-beta.2` | `>=0.31.1, <0.32` | Stable `0.31.x`; `0.32` still beta. |
| `smallvec` | `2.0.0-alpha.12` | `>=1.15, <2` | Stable `1.x`; `2.0` still alpha. |
| `zerocopy` | `0.9.0-alpha.0` | `>=0.8, <0.9` | Stable `0.8.x`; `0.9` still alpha. |

## Validation evidence

`cargo metadata --format-version 1` on the resulting `Cargo.toml` resolves
**305 packages** to "latest Rust 1.85.0 compatible versions". `cargo check
--workspace --all-targets` and `cargo clippy --workspace --all-targets --
-D warnings` both exit 0. `cargo fmt --all --check` is clean.

## 1. Heavy sys-crate gating (Tasks 2 + 4 prelude)

One workspace dependency still needs host packages beyond a clean Rust toolchain:

| Crate | Failure mode | Root cause | Resolution |
|---|---|---|---|
| `bitcoinkernel` (`libbitcoinkernel-sys` 0.2.0) | `cmake` aborts: "Could NOT find Boost (missing: Boost_DIR)" | The crate vendors libbitcoinkernel C++ sources and builds them via CMake; **Boost development headers (`libboost-dev`) are required**. | Feature-gate behind `kernel` in `crates/consensus/Cargo.toml`. Default build skips the kernel; CI installs `libboost-dev` only in the `kernel-only` job and enables the feature explicitly. |

### MDBX un-gated after MSRV 1.92

`signet-libmdbx` 0.8.3 previously required `signet-mdbx-sys@0.1.0`, whose
minimum supported Rust version is 1.92. The workspace toolchain is now 1.95.0,
so MDBX no longer needs an elevated-toolchain CI lane.

### Resulting feature flags

- `crates/consensus`: `kernel` feature enables `bitcoinkernel` dep and is the production consensus default (**Default ON** across consensus, node, and binary crates). The obsolete `bitcoinconsensus` feature chain was removed.
- `crates/storage`: `rocksdb`, `fjall`, `redb`, `mdbx` features (all enabled by default in binary; node defaults `fjall,kernel`).
- Default builds link `bitcoinkernel` and require system dependencies (`cmake` and `libboost-dev`).
- Workspace CI: `clippy`/`test` jobs build with `FULL_NODE_FEATURES: "rocksdb,fjall,redb,mdbx,kernel"` under Rust 1.95.0 with `libboost-dev` and `cmake` installed up front. The obsolete `kernel-node` job is replaced by `kernel-parity`, while `portable-check` exercises the `--no-default-features` path without C++ build dependencies.

### What this means for PLAN.md gates

- **G3 (kernel parity)** is exercised on the default build via `kernel-parity`; default builds validate all script classes through bitcoinkernel.
- **G7 (4-backend equivalence)** runs in the default full-node CI matrix: rocksdb ↔ fjall ↔ redb ↔ mdbx.
- All other gates (G1, G2, G4, G5, G6, G8 – G14) are unaffected.
## 2. Task 3 — script interpreter v1 wraps bitcoin crate

Task 3 Step 2 calls for a hand-rolled per-opcode dispatcher. The v1 script
crate instead exposes the planned `Interpreter` surface while delegating legacy
and segwit script execution to `bitcoin::Script::verify_with_flags`, backed by
the `bitcoinconsensus` feature. This keeps consensus script behavior tied to
Core's audited implementation while the rest of the public surface lands:
bounded stack infrastructure, opcode re-exports, sigop counters, sighash cache,
taproot helpers, and the Rayon-backed Schnorr batch shape.

The hand-rolled dispatcher remains a follow-up behind a `hand-rolled` cargo
feature. It must ship with a parity-vs-bitcoin-crate test before replacing the
delegated v1 path, so downstream callers do not observe an API change.

### v1 taproot coverage gap

The `bitcoinconsensus` C library that backs `bitcoin::Script::verify_with_flags`
does not validate taproot rules under `VERIFY_ALL`. The v1 `Interpreter`
therefore:

- Verifies legacy + segwit-v0 scripts via `verify_with_flags` (full).
- Verifies **single-input** taproot key-path spends via a local BIP341 sighash +
  `secp256k1::verify_schnorr` path.
- **Returns `ScriptError::TaprootPrevoutsUnavailable`** for multi-input taproot
  spends, and does **not** execute tapscript (BIP342) opcodes at all.
- Sigop counting omits taproot's per-input weight contribution.

**Consequence:** the default-features build can validate everything up through
Taproot activation (block 709632) for single-input taproot transactions only.
Multi-input taproot and tapscript spends require the `kernel` feature
(libbitcoinkernel). Future work, behind a `hand-rolled` feature in
`crates/script`, ships the missing BIP341/BIP342 interpreter coverage.


### Current State Cutover (Tasks 16–18)

The pre-cutover delegation to `bitcoinconsensus` and its associated Taproot coverage gap were resolved by making `bitcoinkernel` (`libbitcoinkernel`) the default production consensus engine across consensus, node, and binary crates. The `bitcoinconsensus` feature chain and backend were removed.

- **Forcing Event:** Mainnet IBD twice stopped at block 938344 under the pre-cutover default (first due to missing complete prevouts, then due to unsupported Taproot script-path witness validation in the Rust/bitcoinconsensus path).
- **Landed Posture:** Default builds link `bitcoinkernel` and require system dependencies (`cmake` and `libboost-dev`). `bitcoinkernel` validates all script classes (legacy, segwit, and Taproot key-path and script-path spends).
- **Portable Posture:** The Rust interpreter is retained under `--no-default-features` as an explicit portable posture for differential testing without C++ dependencies, but cannot validate mainnet Taproot script-path scripts.
### v1 legacy sighash + `OP_CODESEPARATOR`

`bitcoin::sighash::SighashCache::legacy_signature_hash` rejects scripts that
contain `OP_CODESEPARATOR` (Core's pre-segwit handling is removed in the Rust
port). The `sighash.json` vector runner skips rows whose script-code contains
`OP_CODESEPARATOR` and reports the count in the test output. The skipped rows
are a known v1 gap covered by the same `hand-rolled` follow-up.

## 3. Task 9 — BIP157/158 vector-compatible byte order and SipHash rounds

Task 9 says filter headers are `sha256d(prev_header || sha256d(filter_bytes))`
and names `SipHash-1-3` for GCS element hashing. Bitcoin Core's
`blockfilters.json` vectors and implementation use
`sha256d(sha256d(filter_bytes) || prev_header)` for BIP157 filter headers and
`CSipHasher`, Core's SipHash-2-4 implementation, for BIP158 range hashing.

The filters crate follows Bitcoin Core's vector-compatible behavior because the
Task 9 acceptance test explicitly requires byte-identical filter and header
matches against `bitcoin/src/test/data/blockfilters.json`.

## §4 — T18 node lifecycle scaffold

The `bitcoin-rs-node` crate landed with the lifecycle skeleton (config
layering, tracing, metrics in-process, signal-bridge, graceful drain,
crash-recovery sidecar) but does NOT yet construct chain / utxo /
mempool / index / p2p / rpc / electrum subsystems. `EventLoop::spin`
handles shutdown + tick channels only; tick handlers are stubs.
Subsystem wiring lands in a follow-up.

- Files: `crates/node/src/{config.rs,state.rs,run.rs,event_loop.rs,crash_recovery.rs,signal.rs,shutdown.rs,logging.rs,metrics.rs,bitcoin_conf_compat.rs}`
- Commit: 33333f9 + 304259f

## §5 — T19 bin wiring + clap exit handling

`bin/bitcoin-rs/src/main.rs` boots `Config::load_from_args` →
`node::run`. `Config::load_from_args` distinguishes `clap::Error` kinds
`DisplayHelp` / `DisplayVersion` and calls `err.exit()` so `bitcoin-rs
--help` and `--version` return exit code 0 — the standard clap idiom.
A `utreexo` feature was added to `crates/node/Cargo.toml` as a
passthrough to `dep:bitcoin-rs-utreexo` to make the bin's feature table
resolvable.

- Files: `bin/bitcoin-rs/{Cargo.toml,src/main.rs,tests/cli_help.rs}`, `crates/node/{Cargo.toml,src/config.rs}`
- Commit: 47af93b

## §6 — T20 gates scaffold + integration-layer deferral

G1..G14 acceptance tests are scaffolded under
`bin/bitcoin-rs/tests/gates/`. Live-infrastructure gates (G1, G2, G3,
G5, G6, G8, G9, G14) are `#[ignore]`d with run instructions in
doc-comments. Wrapper gates (G4, G7, G10, G11, G12) shell out to
in-tree crate tests. G13 (lints clean) is `#[ignore]`d because CI
already runs clippy in a dedicated job; the gate body documents the
exact invocation.

The `"faster than Bitcoin Core"` performance budget claim (G14) cannot
be validated in-session — it requires multi-day mainnet IBD benchmarks
against a reference bitcoind. The gate is scaffolded as a structural
placeholder. Live infrastructure runs are operator responsibilities.

- Files: `bin/bitcoin-rs/{Cargo.toml,tests/gates/g{01..14}_*.rs}`
- Commit: 144e2c1 + 61ae824

## §7 — Integration layer: NodeState wiring + listeners + synthetic apply_block

Follow-up to §4..§6. The session that opened with the T18..T20 scaffold
closed by wiring the source-of-truth subsystem handles into the node
lifecycle. The wiring covers the active-chain consensus pipeline through
PoW, header-side and block-apply DAA `nBits` continuity/retarget checks,
non-contextual rules, BIP30/34, contextual BIP113/BIP68 checks, BIP9
CSV/Segwit activation, BlockTree insertion, and script verification. The P2P
handshake, per-peer
outbound queues, block-sync `getheaders` / `getdata` download loop, and bounded
server-side `getheaders` / `getdata` responses are wired; persisted block-body
serving remains deferred.

### What is now wired

- `NodeState::open` constructs the canonical Arc handle set: `Arc<UtxoSet>`,
  `Arc<RwLock<Mempool>>`, `Arc<ArcSwapOption<TipSnapshot>>`,
  `Arc<RwLock<Vec<BlockRecord>>>`, `Arc<RwLock<HashMap<Txid, Transaction>>>`,
  `Arc<RwLock<NetworkState>>`, `Arc<ArcSwap<CompactString>>` (mining
  template id).
- `bitcoin_rs_rpc::Context::from_handles` reuses the same Arcs. The
  `rpc_wiring.rs` integration test pins pointer identity across all six.
- `run.rs` orchestrates: open → tracing → crash recovery → shutdown source
  → spawn RPC listener thread (always) → spawn Electrum listener thread
  (when `config.electrum_bind.is_some()`) → spawn one P2P listener thread
  per `config.p2p_listen` address → spin the event loop → graceful drain
  → join each listener.
- RPC, Electrum, and P2P listeners share a `serve_with_shutdown(Arc<AtomicBool>)`
  pattern using non-blocking `accept()` + 100 ms poll.
- `NodeState::apply_block(&Block)` runs the consensus pipeline:
  (1) PoW self-consistency (`header.validate_pow(header.target())`),
  (2) PoW limit (declared target ≤ `Network::max_target()`),
  (3) nBits continuity at non-retarget heights (`block.header.bits == parent.header.bits` unless `height % retarget_interval == 0`),
  (4) non-contextual block rules via `bitcoin_rs_consensus::verify_block_rules_borrowed`
  (empty, missing-coinbase, extra-coinbase, merkle root, witness commitment, block weight),
  (5) BIP30 (best-effort duplicate-txid via UTXO lookup) + BIP34 (per-network activation),
  (6) per-tx script verification with **activation-aware** `VerifyFlags` (P2SH always-on; DERSIG / CLTV / CSV / WITNESS+NULLDUMMY / TAPROOT each gated by `Network::is_*_active(height)`) over a `UtxoSetView` wrapper,
  (7) COINBASE_MATURITY (100-block depth) via `UtxoSet::get_entry` surfacing `(coinbase, height)`,
  (8) UTXO commit (`commit_block`),
  (9) `BlockTree::insert_header(NodeStatus::Active)` — also publishes the new tip via `publish_tip_if_best` on the BlockTree's owned `Arc<ArcSwapOption<TipSnapshot>>`,
  (10) mempool eviction via `Mempool::remove_by_txid`,
  (11) tx-index update for `getrawtransaction`.
  Failed validation at steps 1–8 leaves no orphan header in the BlockTree.
  `import_block` flips `ImportOutcome::applied` to `true` on success.
- **NodeState's `chain_tip` is single-sourced.** `NodeState` caches `Arc::clone(&block_tree.read().tip_handle())` at construction; RPC `Context::from_handles` receives this same Arc. There is no synthetic `self.chain_tip.store(...)` in `apply_block` — the BlockTree publishes the tip via `insert_header`.
- **P2P listener runs full Bitcoin v1 handshake + message-dispatch loop.** `bitcoin_rs_p2p::handshake::run_inbound_handshake` exchanges Version / WtxidRelay / SendAddrV2 / SendHeaders / Verack with the remote. After handshake the per-connection thread enters `run_message_loop` which routes inbound messages via the state-backed dispatch path, sends responses (Pong on Ping, `headers` on `getheaders`, `block` / `notfound` on `getdata`, etc.), and exits cleanly on idle (60s read timeout), wire error, or explicit `Disconnecting`. On exit, the peer is removed from the shared registry via address-match retain.
- **P2P server-side header/block requests are bounded by the active in-memory chain view.** Post-handshake `getheaders` replies are built from the active `BlockTree` and stop at the requested stop hash or the 2,000-header response cap. `getdata` serves active-chain `block` / `witness block` inventory only when the matching body is still present in the shared `BlockRecord` cache; pruned, absent, transaction, compact-block, and unknown inventory is answered with `notfound`. Persisted pruned-body reads remain deferred rather than hidden behind the P2P boundary.
- **Peer registry surfaced via RPC.** `bitcoin_rs_p2p::PeerInfo` (addr, version, services, user_agent, start_height, conn_time, inbound) is collected on handshake success and pushed to `NodeState`'s shared `Arc<RwLock<Vec<PeerInfo>>>`. `rpc::Context::from_handles` takes this handle; `getpeerinfo` enumerates it into Core-compatible JSON; `getconnectioncount` returns the real `len()`.
- `getmempoolinfo` returns real `size`, `bytes`, `total_fee` numbers via `Mempool::stats()`, and `usage` is `Mempool::dynamic_memory_usage()` — the pool's estimated heap, Bitcoin Core's `DynamicMemoryUsage()`. It is an estimate of *this node's* structures, not a reproduction of Core's number, the way Core's own figure estimates boost's containers. **`maxmempool` still bounds the virtual-size sum, not `usage`**, so unlike Core the two are not the same currency and `usage` may exceed `maxmempool`; changing what the limit bounds is a policy change and has not been made.
- `getblock`'s `strippedsize` is the block serialized **without witness data**, derived from BIP141's `weight = base * 3 + total` because rust-bitcoin keeps `Block::base_size` private. It previously reported `size`, which made the two fields agree on every block and hid the witness discount.
- `getblockchaininfo` surfaces real `chainwork` as a 64-character lowercase big-endian hex string via `rpc::Context::chainwork_hex()`.
- `Network::is_{bip34,bip65,bip66,csv,segwit,taproot}_active(height) -> bool` const fns carry the per-network activation tables from Core's `chainparams.cpp`.
- Active-chain DAA retarget validation is wired into header acceptance and `apply_block`: non-retarget heights inherit parent `nBits` unless the network's minimum-difficulty exception applies, retarget heights recompute the expected target over the prior interval with Core's 4x timespan clamp, the network proof-of-work limit cap, and Testnet4's BIP94 period-base rule. Unit coverage pins header pre-insertion rejection, boundary accept/reject cases, clamp behavior, testnet minimum-difficulty exception, and Testnet4 BIP94 behavior.
- Electrum TLS cert config is honored as plaintext-with-warning until a
  matching `electrum_tls_key` field lands; the warning surfaces on every
  boot that configures `electrum_tls_cert` without TLS wiring.

### What is NOT yet wired (consensus correctness gates)

- **No historical DAA fixture parity.** Header acceptance and active-chain retarget calculation are unit-covered, but they are not yet checked against historical mainnet/testnet retarget windows.
- **Contextual transaction checks remain node-local.** BIP113 MTP nLocktime, BIP68 sequence locks, and BIP9 CSV/Segwit activation are wired through the node apply path, but the lower-level consensus crate still exposes `verify_transaction(tx, prevouts, height, flags)` rather than a reusable context-rich transaction API.
- **No persisted block-body serving path for P2P.** P2P `getdata` can serve bodies still present in the in-memory `BlockRecord` cache, but it does not read persisted pruned-body rows after restart or cache eviction; unavailable inventory is reported with `notfound`.
- **No index / filter / coinstats updates triggered by tip advance.** Electrum index, BIP158 filter generation, and coinstats remain stale until a follow-up wires the listener side.
- **G14 empirical validation still deferred.** The `faster than Bitcoin
  Core` claim requires multi-day same-window live mainnet IBD against
  `bitcoin-rs` and `bitcoind`. Operator responsibility.

## §8 — Task 8: index rows carry transaction byte positions

`PLAN.md` Task 8 specifies porting electrs verbatim, and electrs writes
`(8-byte prefix || height)` keys with **empty** values. This implementation puts
a packed `TxPosition[n]` in that unused value: the `(offset, length)` byte range
of every transaction that produced the row, within its block's serialized body.

### Why

Resolution was `O(funding rows x block size)`. `Indexer::resolve_script_history`
loaded and fully decoded the block once per row, then SHA256-hashed every output
script in it. Measured on synthetic fixtures, the cost rose 63.9x for 64x the
rows and 3.6x for 4x the block bytes — the two terms are linear and they
multiply. End-to-end, Electrum `blockchain.scripthash.get_history` cost 86.53 ms
for an address funded at 64 heights, against a G14 budget of 30 ms.

With positions the resolver reads only the named byte ranges. The block-size term
disappears: at 8 funding heights the same call costs 8.95 µs over 250 KB blocks
and 9.12 µs over 1 MB blocks. Full numbers, method, and mutation coverage are in
[`docs/benchmarks/index-read-path.md`](docs/benchmarks/index-read-path.md).

### What this costs

Funding and `TxConfirmed` row storage goes from 12 bytes per row (key only) to
20 (12 key + 8 value), a measured **1.67x** on those two families, uncompressed.
Spending rows are unchanged: nothing resolves them back to transactions today.

### Compatibility

Keys, key ordering and row counts are untouched, so an existing index keeps
working — a row with an empty value takes the whole-block scan path, which is the
verbatim electrs behaviour and is retained as `*_scan`. Nothing forces a reindex;
clearing the index directory and re-syncing is what earns the fast path.

`ColumnFamily::UtxoMeta` carries an `index:format_version` marker, adopted only
when the index is empty. A populated index without one is reported as
`IndexFormat::Legacy` and the node logs a startup warning naming the directory to
delete. It does not refuse to start: reads stay correct either way.

### The rule that makes it safe

Funding and txid keys carry no block identity, so a superseded block at the same
height leaves rows pointing into a different block's bytes. Rather than pay 8
more bytes per row for a block tag, the reader **falls back to a full block scan
the moment any single position fails to resolve**, and never skips a failed
position while keeping the rest. See the *All-or-scan position fallback* concept
in `CONCEPTS.md`. The residual accepted: a stale offset landing exactly on a
transaction boundary whose transaction also matches, while a different
transaction in that block matches too.
