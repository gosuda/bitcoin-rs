# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project goal

Build a robust, correct Bitcoin node. **Minimal-first:** ship the smallest change that satisfies the
requirement and passes the gates; reach for the simplest design that is still correct under adversarial
input. Prefer deleting and reusing over adding; justify every new abstraction by a named invariant it
protects. Robustness is not added later — handle all valid inputs and failure paths in the first cut.

## Build, test, lint

Cargo workspace, Rust 2024 edition, toolchain pinned to 1.95.0 via `rust-toolchain.toml`. The binary's
default features are NOT what CI validates. Always use the portable feature set so local results match CI:

```sh
FEATURES="rocksdb,fjall,redb,mdbx,bitcoinconsensus"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --no-default-features --features "$FEATURES" -- -D warnings
cargo test  --workspace --no-fail-fast   --no-default-features --features "$FEATURES"
```

- Plain `cargo test`/`cargo clippy` (without `--no-default-features --features "$FEATURES"`) tests the
  wrong configuration. Clippy CI runs `-D warnings` — any warning fails the build.
- **`kernel` and `bitcoinconsensus` cannot be enabled in the same binary** (overlapping native Core
  symbols). The kernel path is tested in isolation and needs system `libboost-dev` + `cmake`:
  ```sh
  cargo test -p bitcoin-rs-consensus --no-default-features --features kernel -- --include-ignored
  ```
- Gate tests live in `bin/bitcoin-rs/tests/gates/` (`g01_*`..`g14_*`). Ones marked `#[ignore]` need live
  infrastructure; run with `-- --include-ignored`.

## Lint rules (clippy-enforced at workspace level — these fail CI)

These deviate from std defaults. Don't reach for the std equivalents:

- **Locks:** `parking_lot::Mutex`/`RwLock`, never `std::sync::Mutex`/`RwLock`.
- **Maps:** `hashbrown::HashMap`/`HashTable`, never `std::collections::HashMap`.
- **No `as` casts** — use `TryFrom`/`From` (`as_conversions`, `cast_lossless` are deny).
- **No `unwrap()`, `dbg!`, `todo!`, `unimplemented!`** in code (deny); `expect()` is warn.
- **Every `unsafe` block needs a `// SAFETY:` comment** (`undocumented_unsafe_blocks` is deny).
- **No `mod.rs`** — directory-based modules only (`mod_module_files` is deny).
- Public items need doc comments (`missing_docs` warns, and clippy runs `-D warnings`).
- `pedantic` + `nursery` run at warn; `unsafe_op_in_unsafe_fn` is deny.

## Architecture constraints

- **`crates/wallet` must contain zero private-key surface.** CI fails if
  `SecretKey`/`secp256k1::Secret`/`seckey` appears under `crates/wallet/src`. The wallet is PSBT-only by
  design — signing happens in external signers. This is a constraint, not a limitation.
- **Consensus authority:** `bitcoinkernel` is the source of truth. The parallel Rust validation path must
  produce byte-identical results; if they disagree, kernel wins.
- **Event loop is `crossbeam-channel`-based, not async** (no tokio/async-std).
- **Storage** is a `KvStore` trait with four interchangeable backends (rocksdb default, mdbx, fjall, redb);
  all four must pass the storage-equivalence gate with identical results.
- **`openssl` is banned** (`deny.toml`) — use rustls.

## Commits

Conventional commits: `type(scope): message` (e.g. `fix(node):`, `feat(consensus):`). One logical change
per commit.
