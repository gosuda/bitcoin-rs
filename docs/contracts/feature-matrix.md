# Feature matrix contract

bitcoin-rs supports a small named set of feature combinations. That set
is not the powerset of crate features, and empty backend markers on
crates that do not own storage are not combinations.

## Clauses

### `FEAT-01`: Named supported combinations

- **Owner**: `scripts/feature-matrix.tsv`.
- **Scope**: operator-facing `bitcoin-rs` / `bitcoin-rs-node` backend and
  kernel flags, plus the storage and consensus crates those flags reach.
- Each row is one combination CI must `cargo check` independently.
  `lane=pure` is fjall/redb/zmq with the native interpreter.
  `lane=native` needs cmake/libboost (kernel) and/or C storage engines.
  `bitcoin-rs-node`'s crate default (`fjall,kernel,zmq`) is a native row.
- Adding a Cargo feature is not enough to support a combination. Add a
  row here in the same commit, or do not add the feature.

### `FEAT-02`: Backend forwarding follows `ARCH-03`

- **Owner**: `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`;
  the validator it calls lives in `bin/bitcoin-rs/tests/support/dependency_graph.rs`.
- Backend feature ownership and forwarding are governed by the normative
  `ARCH-03` contract in [architecture.md](architecture.md). In particular,
  layer 0 and RPC, as well as `mempool` and `mining`, must not define backend
  feature names; forwarding is limited to storage and the approved service
  adapters and operator-facing entry points. G17 enforces this constraint.
- Empty backend markers are not combinations; the matrix lists none.

## Proven by

- `scripts/check-feature-matrix.sh` (main workflow `feature-combinations`).
- `cargo test -p bitcoin-rs --test g17_dependency_direction`.
