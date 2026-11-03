# Build and test

Run the smallest gate that covers your change, then run the full gate before you open a pull request. The gate command is [`scripts/ci-pr.sh`](https://github.com/gosuda/bitcoin-rs/blob/main/scripts/ci-pr.sh), and CI invokes the same script.

## Toolchain and build

The workspace uses edition 2024. [`rust-toolchain.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/rust-toolchain.toml) pins the stable channel with `rustfmt` and `clippy`, and a minimal profile. Running `cargo` from the repository root selects that toolchain.

The default build is kernel-free. `cargo build -p bitcoin-rs` uses the native Rust interpreter and links no C++ engine. The `kernel` feature compiles Bitcoin Core's engine in, and it needs `cmake` and `libboost-dev`. The feature is a capability, not a selection: `validation.engine` still chooses the engine at runtime, and `native` stays the default in every build.

## The gates

`./scripts/ci-pr.sh` takes one subcommand:

| Subcommand | What it runs |
| :--- | :--- |
| `fmt` | `cargo fmt --all -- --check` |
| `clippy` | Four kernel-free clippy profiles plus a production `cargo check` for the binary |
| `test-crates` | Library test lanes |
| `test-binary` | Node binary test lane |
| `test-workspace` | Workspace test lane |
| `test` | `test-crates`, then `test-binary`, then `test-workspace` |
| `deny` | `cargo deny` over the full dependency graph, including the kernel feature |
| `contracts` | `cargo run --locked -p contract-index -- --check` |
| `book` | mdBook build of the handbook plus the link check |
| `proofs` | Kani, the Lean pipeline, and the TLA+ model checker |
| `deep` | Clippy and all three test lanes, collecting every failure |
| `all` | `fmt`, `deep`, `deny`, and `contracts` |

`all` deliberately omits `proofs`. CI runners carry no Kani, Lean, or Aeneas toolchain. Run `proofs` yourself when you change a module with a `proofs.rs` file, a `*_model.rs` model, or a Lean file.

The clippy profiles are not one command. The script checks the workspace with `silent-payments` but excludes `bitcoin-rs-consensus`, `bitcoin-rs-chainstate`, and `bitcoin-rs-node`. It then checks each of those three with its own feature set, and adds a production `check` of the `bitcoin-rs` binary. A clippy run over only the workspace misses those per-crate feature sets.

The test lanes use `cargo nextest` when it is installed. Without nextest they fall back to `cargo test --no-fail-fast`. The two runners execute the same tests because the tree has no doctests.

`cargo deny` failures are bug reports, not lint noise. The deny lane resolves the storage backends and the kernel graph without building the kernel.

## The smallest meaningful run

For a change in one crate, start with the narrow test target:

```
cargo test --locked -p bitcoin-rs-primitives --lib
```

Replace the package and target with the owner you changed. A single test name narrows it further:

```
cargo test --locked -p bitcoin-rs-primitives --lib superfluous_segwit_marker_is_rejected
```

That second command ran in this checkout and passed. The exact filter is useful when a contract test names the behavior.

For a formatting-only change, run `./scripts/ci-pr.sh fmt`. For a contract or evidence-index change, run `./scripts/ci-pr.sh contracts`. For a proof-owning change, run `./scripts/ci-pr.sh proofs`.

## What CI runs

Pull requests run `fmt`, `deny`, `contracts`, `clippy`, and `test-crates` in parallel jobs. Merge-group requests add `book`, `test-binary`, and `test-workspace`, plus the kernel-consensus and full-node-compile lanes. Main pushes and manual dispatches add the full-node feature set with the C++ kernel and `--include-ignored` consensus vectors. They also run the kernel oracle, benchmark-smoke compilation, Python comparator tests, the Core differential lane, and native-script evidence.

The compatibility campaign runs MSRV, dependency-range, and feature-matrix lanes. The model-check workflow is manual. The documented lane list is in [`CONCEPTS.md`](https://github.com/gosuda/bitcoin-rs/blob/main/CONCEPTS.md) under CI lane parity, and [`CONTRIBUTING.md`](https://github.com/gosuda/bitcoin-rs/blob/main/CONTRIBUTING.md) owns the pull-request verification rules.

> **Warning** A local `cargo test` is not lane parity. A branch is green only against `scripts/ci-pr.sh`, which is what CI invokes. A local approximation with different features or a different runner never counts.

## Read a gate result

The fmt gate prints nothing when it passes. In this checkout it exited 0. The contracts gate prints the build line and the checker invocation:

```
$ ./scripts/ci-pr.sh contracts
    Finished `dev` profile [optimized + debuginfo] target(s) in 0.13s
     Running `target/debug/contract-index --check`
```

A nonzero exit names the failing profile. `deep` keeps going after a failure and reports every failing profile at the end. `all` runs every subcommand and reports the total at the end.

A skipped test is not a pass. A lane that cannot run for a host reason is reported as `BLOCKED` by its owner, and `BLOCKED` is never green.

Owner: [`scripts/ci-pr.sh`](https://github.com/gosuda/bitcoin-rs/blob/main/scripts/ci-pr.sh). Next: [Contracts and evidence](contracts.md) explains the clause tags, and [Report a security problem](security.md) covers the reporting route that exists.
