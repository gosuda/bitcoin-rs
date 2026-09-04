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
- Adding a Cargo feature is not enough to support a combination. Add a
  row here in the same commit, or do not add the feature.

### `FEAT-02`: No empty backend markers on non-storage crates

- **Owner**: `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`.
- Layer 0 (`consensus`, `script`, `primitives`) and layer 3 (`rpc`)
  define no `rocksdb` / `fjall` / `redb` / `mdbx` features, even empty.
- `mempool` and `mining` likewise: they do not own storage, so they do
  not carry backend feature names. Node forwards backends only into
  crates that actually select an engine (`storage`, `chain`, `utxo`,
  `p2p`, `index`).

## Proven by

- `scripts/check-feature-matrix.sh` (main workflow `feature-combinations`).
- `cargo test -p bitcoin-rs --test g17_dependency_direction`.
