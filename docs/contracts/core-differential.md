# Bitcoin Core differential contract

libbitcoinkernel oracle tests prove consensus-script parity. This page
owns the live Bitcoin Core node differential: observable chain identity
after a real P2P sync, not a replay of captured JSON.

## Clauses

### `CORE-01`: Pinned Core 31.1 bitcoind

- **Owner**: `scripts/install-bitcoind.sh`.
- The live lane downloads Bitcoin Core 31.1
  `bitcoin-31.1-x86_64-linux-gnu.tar.gz` from bitcoincore.org and checks
  the tarball SHA-256 before extracting `bitcoind`.

### `CORE-02`: Observable chain identity matches after P2P sync

- **Owner**: `scripts/run-p2p-core-interop.sh`.
- After bitcoin-rs catches up to Core on regtest, `getblockcount`,
  `getbestblockhash`, and `getblockchaininfo.{chain,blocks}` agree.
- Evidence schema `bitcoin-rs-core-differential-v1` is verified by
  `crates/p2p/tests/core_interop_live.rs`.
- This complements `kernel_block_parity` / `kernel_vector_parity`: those
  tests the C++ engine in-process; this tests a running Core node.

## Proven by

- Main workflow `core-differential`.
- `cargo test -p bitcoin-rs-p2p --test core_interop_live -- --ignored`
  with `P2P_CORE_INTEROP_EVIDENCE` set by the driver.
