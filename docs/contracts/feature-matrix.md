# Feature matrix contract
Named supported combinations only, not the powerset; empty backend markers on non-storage crates are not combinations.
## Clauses
### `FEAT-01`: Named supported combinations
Owner `scripts/feature-matrix.tsv`; scope: operator `bitcoin-rs`/`bitcoin-rs-node` backend and kernel flags plus reached storage/consensus crates. Each row is one combination CI must `cargo check` independently. `lane=pure` carries fjall/redb/zmq and optional `silent-payments` with the native interpreter; `lane=native` needs cmake/libboost (kernel) and/or C storage engines. Kernel rows (`portable-kernel`, `full-node`, `consensus-kernel`) are capability builds with `kernel` compiled in; engine selection stays runtime (`validation.engine`). The `bitcoin-rs-node` crate default (`fjall,zmq`) is a pure row.
Checker selects the repository-root workspace from nested workspaces such as `fuzz/`. Adding a Cargo feature is not enough: add a row here in the same commit, or do not add the feature.
### `FEAT-02`: Backend forwarding follows `ARCH-03`
Ownership and forwarding are governed by `ARCH-03` ([architecture.md](architecture.md)); layer 0 and RPC, `mempool` and `mining` must not define backend feature names; forwarding is limited to storage, approved service adapters, and operator-facing entry points (G17 enforces). Empty backend markers are not combinations; the matrix lists none. Owner: `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs` via `bin/bitcoin-rs/tests/support/dependency_graph.rs`.
Proven by `scripts/check-feature-matrix.sh` (`compatibility-campaign.yml` `feature-combinations` job); `scripts/tests/test_feature_matrix.py` (root and nested resolution; offline regression); `cargo test -p bitcoin-rs --test suite g17_dependency_direction::`.
