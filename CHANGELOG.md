# Changelog

## Unreleased

- Verified snapshot state for AssumeUTXO import (`crates/storage/src/utxo/core_snapshot.rs`, `crates/execution/src/assumeutxo.rs`, `crates/node/src/snapshot.rs`). `read_verified` seals the decoded portable set with its base hash, height, commitment and coin statistics, so portable activation performs no second commitment pass or statistics scan. Sets that arrive without proof (native v4 input) are verified exactly once under the lifecycle lock. Caller digests and snapshot trailers still establish no trust. Recorded compatibility boundary: files repeating txid groups are refused (`TransactionOrder`, RPC `-22`); Core 31.1 accepts such a file. No performance gain is claimed.
