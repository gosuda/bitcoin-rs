# bitcoin-rs

Ultra-fast Bitcoin full node in Rust 2024.

Single binary. Native UTXO set (gocoin-shape). Embedded Electrum-style index
(electrs-shape). Optional utreexo accumulator (utreexod-shape). In-process
PSBT-only wallet (no private keys). In-process getblocktemplate mining.
Pruning. BIP157/158 compact filters. coinstats. Four pluggable storage
backends (RocksDB / MDBX / fjall / redb). SIMD JSON on the RPC hot path.

Status: in active implementation. See [`PLAN.md`](PLAN.md).

License: MIT OR Apache-2.0.
