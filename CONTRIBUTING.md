# Contributing to bitcoin-rs

Thank you for contributing to `bitcoin-rs`. This guide outlines the development
workflow, coding standards, and verification commands used across the project.

## Prerequisites

- Use the current stable Rust toolchain (Rust 2024 edition).
- Install C/C++ build tools for native dependencies such as ZeroMQ. The default
  binary excludes `libbitcoinkernel`, but this does not make every dependency
  Rust-only.
- Kernel-enabled checks additionally require CMake and Boost headers
  (`cmake` and `libboost-dev` on Debian/Ubuntu). Checks that build the
  `rocksdb` backend (notably the dependency-range minimal lane, which
  checks `--all-features`) additionally require libclang (`libclang-dev`
  on Debian/Ubuntu). No manifest enables `kernel` by default: the feature is
  an opt-in capability on the consensus, node, and binary crates, and engine
  selection is the runtime `validation.engine` setting. The exact defaults are
  owned by the
  [validation-default contract](docs/contracts/validation-default.md).
- The PR comparator tests use Python 3.13. Fuzzing and dependency/feature
  matrix checks also need the tools described in the main workflow below.

From the repository root, install and select stable:

```sh
rustup toolchain install stable --component rustfmt --component clippy
rustup override set stable
cargo install --locked cargo-deny
cargo install --locked cargo-nextest --version 0.9.143  # optional: speeds the test lanes up; ci-pr.sh falls back to cargo test
```

[`rust-toolchain.toml`](rust-toolchain.toml), CI, pre-commit hooks, and the
local commands above all select stable. Explicit `+nightly` commands below are
limited to checks that require nightly Rust.

Start with the affected package or test while developing, then run the
applicable CI checks before submitting. The workflow files define the complete
job set.

## Pull-request verification

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs for pull requests
against any base branch, including stacked PRs, and for pushes to `main`. Its
jobs are `fmt`, `deny` (parallel, no workspace compile), `clippy`, and three
test lanes (`test-crates`, `test-binary`, `test-workspace`), all parallel;
every lane fails fast at its first failing profile, so the first actionable
failure is not delayed behind unrelated profiles (issue #1081). Every gate
command lives in [`scripts/ci-pr.sh`](scripts/ci-pr.sh) -- CI, the
pre-commit hooks, and this guide all invoke that script, so the commands
cannot drift:

```sh
./scripts/ci-pr.sh fmt            # format check
./scripts/ci-pr.sh clippy         # three kernel-free all-target profiles
./scripts/ci-pr.sh test-crates    # consensus, node, rpc profiles (fixture-free)
./scripts/ci-pr.sh test-binary    # binary profile (rocksdb,fjall,redb)
./scripts/ci-pr.sh test-workspace # workspace kernel-free pass
./scripts/ci-pr.sh test           # every test lane in sequence, smallest first
./scripts/ci-pr.sh deny           # full dependency graph, metadata only
./scripts/ci-pr.sh deep           # every profile, collecting all failures
./scripts/ci-pr.sh all            # fmt + deep + deny
```

In CI the test lanes run under cargo-nextest's pooled scheduler and link
with mold (`.github/actions/test-deps` installs both); where nextest is not
installed the script falls back to `cargo test --no-fail-fast`, so local
runs and hooks need no extra tooling.

Plain `cargo test --workspace` and `cargo clippy --workspace` also enable the
library defaults, which are now kernel-free (the `kernel` feature is an opt-in
capability; the engine a run uses is `validation.engine` at runtime), so plain
workspace commands need no C++ toolchain. The script passes the kernel-free
feature selection. The binary and workspace test lanes expect the
pinned Core fixture:
`bash scripts/provision-ci-reference-fixtures.sh core`.

Formal evidence has its own lane: provision with
`bash scripts/provision-ci-reference-fixtures.sh formal`, then run
`python3 scripts/check_models.py`. A `--check-only` invocation checks custody,
not model properties. Benchmark evidence checks run with
`cargo test --locked -p bitcoin-rs-node --no-default-features --features fjall --bench evidence`.

The [pre-commit configuration](.pre-commit-config.yaml) runs the same script,
so local hooks are the kernel-free PR gate, not the C++ full-node lane.

Deep lanes -- the kernel C++ surface (full-node tests, bench smoke with the
witness-activation regression and the SegWit-v0 kernel oracle), the MSRV
compile, native-script evidence, the comparator corpus, fuzzing, and the
dependency/feature matrices -- run on `main` only; see the next section and
the jobs in [`.github/workflows/main.yml`](.github/workflows/main.yml).

## Deep CI lanes (main workflow)

[`.github/workflows/main.yml`](.github/workflows/main.yml) runs kernel-enabled
tests, fuzzing, dependency/feature matrices, and the main-only verification
lanes -- bench smoke (with the witness-activation kernel regression and the
SegWit-v0 kernel oracle), the MSRV compile, native-script evidence, and the
comparator corpus -- on pushes to `main` and manual dispatch.
Pull-request-triggered checks are defined in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

### Full-node feature set

Compiles all retained storage engines (`fjall`, `redb`, `rocksdb`) and the
`libbitcoinkernel` verification oracle (requires `cmake` and `libboost-dev`):

```sh
cargo test -p bitcoin-rs --no-fail-fast \
  --no-default-features --features "rocksdb,fjall,redb,kernel"

cargo clippy -p bitcoin-rs --all-targets \
  --no-default-features --features "rocksdb,fjall,redb,kernel" -- -D warnings

cargo clippy -p bitcoin-rs-node --all-targets -- -D warnings
cargo clippy -p bitcoin-rs-consensus --all-targets -- -D warnings
```

### Consensus test vectors and parity gate

```sh
# Run deterministic consensus vectors
cargo test -p bitcoin-rs-consensus --no-fail-fast -- --include-ignored

# Run differential kernel parity verification (requires kernel feature)
cargo test -p bitcoin-rs-consensus --features kernel \
  --test kernel_block_parity --test kernel_vector_parity -- --nocapture
```

The two parity test targets are not ignored. Passing `--ignored` would skip
them rather than run the oracle checks.

### Benchmark compilation check

The main workflow compiles the retained crate-level benchmarks without kernel,
under the `quickstart` profile (the `bench` profile's fat-LTO build is too
expensive for a compile-only gate):

```sh
cargo bench -p bitcoin-rs-consensus --no-run --no-default-features --bench merkle --profile quickstart
cargo bench -p bitcoin-rs-mining --no-run --no-default-features --bench candidate --profile quickstart
cargo bench -p bitcoin-rs-utxo --no-run \
  --no-default-features --features fjall --bench utxo_commit --profile quickstart
cargo bench -p bitcoin-rs-node --no-run \
  --no-default-features --features fjall --bench sync_pipeline --profile quickstart
cargo bench -p bitcoin-rs-node --no-run \
  --no-default-features --features fjall --bench chainstate_journal --profile quickstart
```

`--no-run` checks compilation; it produces no performance measurement.

The same `bench-smoke` job also compiles the kernel-enabled binary-package
benches (`--features rocksdb,fjall,redb,kernel`), runs the witness-activation
kernel regression, and checks the SegWit-v0 kernel oracle with retained
diagnostics.

### Fuzzing

Fuzz targets live under `fuzz/` and run against imported corpora:

```sh
# Install the fuzz toolchain and runner if not present
rustup toolchain install nightly
cargo install cargo-fuzz

# Run a target (options: p2p_message, block_validate, tx_validate, script_eval, utxo_snapshot)
cargo +nightly fuzz run block_validate --target x86_64-unknown-linux-gnu -- -runs=10000
```

CI builds and runs all five targets: `p2p_message`, `block_validate`,
`tx_validate`, `script_eval`, and `utxo_snapshot`. See [`fuzz/README.md`](fuzz/README.md) for
local fuzzing and corpus guidance.

The companion corpus repository is
[gosuda/bitcoin-rs-fuzz-corpus](https://github.com/gosuda/bitcoin-rs-fuzz-corpus).
For local campaigns, see [shared corpus and local campaigns](fuzz/README.md#shared-corpus-and-local-campaigns)
for a separate writable corpus and contribution guidance. The scheduled
campaign is defined in [`.github/workflows/daily-fuzz.yml`](.github/workflows/daily-fuzz.yml).

### Dependency-range check

Prove the declared ranges, not only the committed lockfile
(`docs/contracts/dependency-range.md`):
This lane changes `Cargo.lock`. Run it in a disposable checkout, with nightly
and kernel build dependencies installed:

```sh
# Oldest allowed direct-dependency versions (nightly, mutates Cargo.lock)
scripts/check-dep-range.sh minimal

# Newest versions still inside each declared range (mutates Cargo.lock)
scripts/check-dep-range.sh maximum
```

The original `Cargo.lock` is restored on exit unless `KEEP_LOCK=1`.
Each lane also runs `cargo deny check bans` against the mutated lockfile.
Optional native storage backends are owned by the named feature matrix, not
this script.

### Bitcoin Core differential

Live observable-behavior check against a pinned Core 31.1 `bitcoind`
(`docs/contracts/core-differential.md`):

```sh
scripts/run-p2p-core-interop.sh \
  --bitcoind-command "$(scripts/install-bitcoind.sh)" \
  --bitcoin-rs-command target/quickstart/bitcoin-rs
```

### Feature combinations

The supported combinations are the rows in
`scripts/feature-matrix.tsv`, not a feature powerset:

```sh
scripts/check-feature-matrix.sh        # every row (needs cmake/libboost for kernel)
scripts/check-feature-matrix.sh pure   # fjall/redb/zmq only
```

## Architecture and contribution scope

Read [AGENTS.md](AGENTS.md), the relevant issue or PR, and the owning
[contract](docs/contracts/README.md) before changing a subsystem. The
[architecture contract](docs/contracts/architecture.md) owns the five-layer
crate assignments, dependency direction, storage isolation, and their
verification gate. The [validation-default contract](docs/contracts/validation-default.md)
owns script-engine selection and its promotion criteria.

Keep implementation guidance with its owner rather than introducing another
architecture or validation specification in this guide.

## Commit and PR conventions

- Commit style: capitalized imperative subject line under 72 characters (for example, `Own Bitcoin protocol primitives natively`).
- Commit body: explain what changed and why. Include relevant issue numbers in footers (`Closes #N` or `Fixes #N`).
- Atomic changes: keep commits self-contained and bisectable; the workspace should compile and pass tests at each step.
- Tests first: bug fixes should include regression tests proving the defect is resolved.

## Documentation references

- [docs/README.md](docs/README.md) — Documentation index
- [docs/contracts/](docs/contracts/) — Normative architectural and protocol contracts
- [docs/getting-started.md](docs/getting-started.md) — Node setup and configuration
- [CONCEPTS.md](CONCEPTS.md) — Domain terminology and concepts
