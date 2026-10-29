# Contributing to bitcoin-rs

This guide covers the development workflow, coding standards, and verification commands used across the project.

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
  an opt-in capability on the consensus, script, chainstate, node, and binary
  crates, and engine
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
against any base branch (including stacked PRs), on merge-group requests, and
for pushes to `main`. PR green is fast feedback only: `fmt`, `deny`,
`clippy`, and `test-crates` passed while `test-binary` and `test-workspace`
are skipped. Merge-group green adds those two heavy lanes as the pre-main
integration signal; main checks are post-merge evidence. Every lane fails
fast at its first failing profile. Every gate command lives in
[`scripts/ci-pr.sh`](scripts/ci-pr.sh), which CI, the pre-commit hooks, and
this guide all invoke:

```sh
./scripts/ci-pr.sh fmt            # format check
./scripts/ci-pr.sh clippy         # four kernel-free all-target Clippy profiles + production silent-payments check
./scripts/ci-pr.sh test-crates    # per-crate profiles, including checked-in fixtures
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

### Merge queue and integration contract

All merges to `main` must pass through the GitHub merge queue. Direct merges
bypassing the queue are disallowed for standard pull requests.

The merge queue enforces the integration contract on the latest combined ref
(`merge_group`) before updating `main`:
- **PR green (`pull_request`)**: Fast feedback only. `ci-gate` requires `fmt`,
  `deny`, `clippy`, and `test-crates`; `test-binary`, `test-workspace`, and
  kernel/native checks are skipped to keep feedback fast (<3 min).
- **Merge-group green (`merge_group`)**: Pre-main integration eligibility.
  `ci-gate` strictly requires `test-binary` and `test-workspace`;
  [`ci-merge-gate.yml`](.github/workflows/ci-merge-gate.yml) strictly requires
  `kernel-consensus` and `full-node-compile`.
- **Main green (`push`)**: Post-merge historical evidence. Runs extended
  campaigns and reference verifications in [`main.yml`](.github/workflows/main.yml).

Required status checks in repository branch rulesets (`ci-gate`,
`kernel-consensus`, `full-node-compile`) enforce this boundary, guaranteeing
that heavy integration and production compilation checks have passed on the
current base before `main` moves forward.

## Post-merge CI lanes

[`.github/workflows/main.yml`](.github/workflows/main.yml) runs kernel-enabled
tests and the main-only verification lanes on pushes to `main` and manual
dispatch: bench smoke (with the witness-activation kernel regression and the
SegWit-v0 kernel oracle), native-script evidence, the comparator corpus, and
Core differential.
Pull-request-triggered checks are defined in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) and the path-scoped
[`fuzz-build.yml`](.github/workflows/fuzz-build.yml).

### Full-node feature set

Compiles all retained storage engines (`fjall`, `redb`, `rocksdb`) and the
`libbitcoinkernel` verification oracle (requires `cmake` and `libboost-dev`):

```sh
cargo test -p bitcoin-rs --no-fail-fast \
  --no-default-features --features "rocksdb,fjall,redb,kernel"

cargo clippy -p bitcoin-rs --all-targets \
  --no-default-features --features "rocksdb,fjall,redb,kernel" -- -D warnings

cargo clippy -p bitcoin-rs-node --all-targets --features kernel -- -D warnings
cargo clippy -p bitcoin-rs-consensus --all-targets --features kernel -- -D warnings
```

### Consensus test vectors and parity gate

```sh
# Run deterministic consensus vectors
cargo test -p bitcoin-rs-consensus --no-fail-fast -- --include-ignored

# Run differential kernel parity verification (requires kernel feature)
cargo test -p bitcoin-rs-consensus --features kernel \
  --test suite -- kernel_block_parity:: kernel_vector_parity:: --nocapture
```

The tests in both parity modules are not ignored. Passing `--ignored` would skip
them rather than run the oracle checks.

### Benchmark compilation check

The main workflow compiles the retained crate-level benchmarks without kernel,
under the `quickstart` profile:

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

[`fuzz-build.yml`](.github/workflows/fuzz-build.yml) builds all five targets
on `fuzz/**` pull requests; the scheduled campaign is defined in
[`.github/workflows/daily-fuzz.yml`](.github/workflows/daily-fuzz.yml). See
[`fuzz/README.md`](fuzz/README.md) for local fuzzing, the
[shared corpus and local campaigns](fuzz/README.md#shared-corpus-and-local-campaigns),
and the companion [corpus repository](https://github.com/gosuda/bitcoin-rs-fuzz-corpus).

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
CI runs these endpoints in the scheduled/manual
[`compatibility-campaign.yml`](.github/workflows/compatibility-campaign.yml).

### Bitcoin Core differential

Live observable-behavior check against a pinned Core 31.1 `bitcoind`
([`docs/contracts/core-differential.md`](docs/contracts/core-differential.md),
reproduction details in [`docs/validation-tooling.md`](docs/validation-tooling.md#1-live-bitcoin-core-p2p-and-chain-identity-differential)):

```sh
cargo build --locked -p bitcoin-rs --profile quickstart --no-default-features --features fjall,zmq
scripts/run-p2p-core-interop.sh \
  --bitcoind-command "$(scripts/install-bitcoind.sh --print-path)" \
  --bitcoin-rs-command target/quickstart/bitcoin-rs
```

### Feature combinations

The supported combinations are the rows in
`scripts/feature-matrix.tsv`, not a feature powerset:

```sh
scripts/check-feature-matrix.sh        # every row (needs cmake/libboost for kernel)
scripts/check-feature-matrix.sh pure   # fjall/redb/zmq only
```

CI runs the matrix and the MSRV gate in the scheduled/manual
[`compatibility-campaign.yml`](.github/workflows/compatibility-campaign.yml).

## Architecture and contribution scope

Read [AGENTS.md](AGENTS.md), the relevant issue or PR, and the owning
[contract](docs/contracts/README.md) before changing a subsystem. The
[architecture contract](docs/contracts/architecture.md) owns the five-layer
crate assignments, dependency direction, storage isolation, and their
verification gate. The [validation-default contract](docs/contracts/validation-default.md)
owns script-engine selection and its promotion criteria.

Keep implementation guidance with its owner instead of adding another
architecture or validation specification here.

Follow the [source and test organization policy](docs/policies/source-organization.md)
when adding or reorganizing modules, tests, and fixtures.

## Proposing and implementing BIPs

External BIP authors and implementers are welcome to propose, prototype, and
implement BIP-based capabilities in `bitcoin-rs`. The
[BIP adoption policy](docs/policies/bip-adoption.md) governs evaluation and
lifecycle decisions; contributors can follow this lightweight path:

1. **Propose:** Open an ordinary GitHub issue (or join an existing discussion)
   with a link to the BIP or pinned draft revision, the intended node-facing
   use case, and an initial validation or interoperability idea. Non-consensus
   BIPs are explicitly welcome **before Bitcoin Core merges or ships them**; a
   Core merge is not a prerequisite for proposing or exploring an idea here.
2. **Experiment:** Small, reversible, opt-in (default-off) implementation PRs
   are welcome. State which existing crate and state owner the implementation
   extends, and provide the first bounded proof (such as reference vectors,
   codecs, or a regtest prototype). Full production interoperability evidence
   is not required just to explore or merge an isolated experiment.
3. **Validate and promote:** Merging an experimental implementation is distinct
   from declaring production or `Shipped` compatibility. Promotion requires the
   policy's stronger external-consumer evidence, sync safety, and measured
   resource costs. Review is grounded in consensus invariance, synchronization
   safety, clean ownership, and bounded overhead, not whether Core accepted the
   idea first.

This workflow is intentionally lightweight: there is no separate BIP registry,
governance committee, scorecard, mandatory proposal template, or custom CI gate.
See [`docs/policies/bip-adoption.md`](docs/policies/bip-adoption.md) for detailed
lifecycle criteria and [docs/bip-support.md](docs/bip-support.md) for the
current coverage map.

## Commit and PR conventions

- Commit style: capitalized imperative subject line under 72 characters (for example, `Own Bitcoin protocol primitives natively`).
- Commit body: explain what changed and why. Include relevant issue numbers in footers (`Closes #N` or `Fixes #N`).
- Atomic changes: keep commits self-contained and bisectable; the workspace should compile and pass tests at each step.
- Tests first: bug fixes should include regression tests proving the defect is resolved.

### Architectural changes

The project boundary is stable external contracts, replaceable internal
architecture. Internal breaking changes are acceptable with clear rationale;
breaking a supported external contract is a regression. For a change that
reshapes internals, reviewers evaluate:

1. **External contract preserved?** Consensus, P2P, and every affected
   supported external API keep observable behavior, proven with the
   regression, differential, or black-box evidence the owning contract names.
2. **Better internals?** A concrete improvement, clearer ownership, simpler
   boundaries, reduced duplication, measurable performance, or more reliable
   recovery, with its migration/resync and operational cost assessed.
3. **No compatibility debt without a requirement?** No legacy adapters, dual
   paths, migration layers, or dead internal interfaces kept solely to avoid
   an intentional internal break.
4. **Fail safely?** Durable-format changes keep explicit format gates, crash
   consistency, and fail-closed recovery; external contracts do not regress.

A breaking change is permitted, not a goal. The more aggressively internals
are redesigned, the stronger the external validation evidence must be.

## Documentation references

- [docs/README.md](docs/README.md): documentation index
- [docs/contracts/README.md](docs/contracts/README.md): normative architectural and protocol contracts
- [docs/validation-tooling.md](docs/validation-tooling.md): validation tooling and differential evidence lanes
- [docs/getting-started.md](docs/getting-started.md): node setup and configuration
- [CONSTRAINTS.md](CONSTRAINTS.md): repository-wide project invariants
- [CONCEPTS.md](CONCEPTS.md): domain terminology and concepts

Documentation follows the [ownership policy](docs/policies/documentation.md): keep requirements with their enforcing owners and current execution evidence with CI or the PR.
