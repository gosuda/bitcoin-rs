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
