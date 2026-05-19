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
MSRV is 1.92. The workspace MSRV is now 1.92.0, so MDBX no longer needs an
elevated-toolchain CI lane.

### Resulting feature flags

- `crates/consensus`: `kernel` feature → enables `bitcoinkernel` dep + the dual-path validator. **Default off.**
- `crates/storage`: `rocksdb`, `fjall`, `redb`, `mdbx` features. Default: `rocksdb`.
- Workspace CI: `clippy`/`test` jobs build with `--no-default-features --features rocksdb,fjall,redb,mdbx` under MSRV 1.92.0. The `kernel-only` job installs `libboost-dev` and adds `kernel` on top of that portable feature set.

### What this means for PLAN.md gates

- **G3 (kernel parity)** still runs in CI, but only on the `kernel-only` job — the gate is gated on the kernel feature, not on every PR.
- **G7 (4-backend equivalence)** now runs in the default portable CI matrix: rocksdb ↔ fjall ↔ redb ↔ mdbx.
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
lifecycle. The wiring is real but **synthetic in the consensus sense**:
blocks are accepted without consensus validation.

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
- `NodeState::apply_block(&Block)` advances the synthetic chain tip on
  header continuity, commits block outputs to `UtxoSet` via
  `commit_block`, evicts confirmed txs from `Mempool` via
  `remove_by_txid`, and indexes the block's transactions for
  `getrawtransaction`. `bitcoin_rs_node::import::import_block` flips
  `ImportOutcome::applied` to `true` on successful apply.
- `getmempoolinfo` returns real `size`, `bytes`, `total_fee` numbers via
  `Mempool::stats()`.
- Electrum TLS cert config is honored as plaintext-with-warning until a
  matching `electrum_tls_key` field lands; the warning surfaces on every
  boot that configures `electrum_tls_cert` without TLS wiring.

### What is NOT yet wired (consensus correctness gates)

- **No consensus validation in `apply_block`.** Only `prev_blockhash ==
  current_tip.hash` is checked. No PoW verification, no merkle root
  check, no script verification, no BIP30/34/65/66/68/112/141/143 rules,
  no BIP9 deployment state. The chain advance is observable but invalid
  by Bitcoin consensus.
- **No real block-tree maintenance.** `BlockTree::accept_header` is not
  called by `apply_block`. The chain is a flat list of `TipSnapshot`s
  without reorg-planning state.
- **No P2P handshake.** The listener accepts and drops the connection
  before any Version/Verack exchange. Peers cannot talk to the node yet.
- **No block download orchestrator.** No code path connects accepted
  peers to `import_block`; `import_block` only fires from tests.
- **No index / filter / coinstats updates triggered by tip advance.**
  Electrum index, BIP158 filter generation, and coinstats remain stale
  until a follow-up wires the listener side.
- **G14 empirical validation still deferred.** The `faster than Bitcoin
  Core` claim requires multi-day live mainnet IBD against `bitcoind`
  and `gocoin`. Operator responsibility.
