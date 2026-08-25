# bitcoin-rs-pruning

Deletion of historical block bodies and undo records under a `PrunePolicy` whose
retention shapes match Bitcoin Core semantics, once the active chain no longer needs
them.

`stage_block_and_undo_prune` is the main entry point: it stages block-body and
undo-row deletion together with prune-height metadata into one caller-owned atomic
batch, so node wiring commits them in a single backend commit. Undo rows are pruned
against the durable tip rather than the in-memory tip — a crash restores to the last
durable checkpoint and must still be able to disconnect back through it, while block
bodies are re-downloadable and are not held to that constraint. After the index rows
commit, `reclaim_staged_flat_block_files` deletes the staged flat block files.
`PruneOutcome` reports the bytes and row counts freed by a pass. The per-row machinery
lives in `block_pruner` (`BlockPruner`, `block_body_key`, `BLOCK_DATA_CF`) and
`undo_pruner` (`UndoPruner`, `block_undo_key`), and the staging helpers in `lib.rs` coordinate block-body deletion.

## Features
- `rocksdb`: forward the rocksdb storage backend to `bitcoin-rs-storage`.
- `fjall`: forward the fjall storage backend to `bitcoin-rs-storage`.
- `redb`: forward the redb storage backend to `bitcoin-rs-storage`.
- `mdbx`: forward the mdbx storage backend to `bitcoin-rs-storage`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
