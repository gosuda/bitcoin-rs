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
- A cached prefix is reused only when its stamp matches that SHA-256 and
  `bitcoind -version` reports `v31.1`.

### `CORE-02`: Observable chain identity matches after P2P sync

- **Owner**: `scripts/run-p2p-core-interop.sh`.
- After bitcoin-rs catches up to Core on regtest, `getblockcount`,
  `getbestblockhash`, and `getblockchaininfo.{chain,blocks}` agree.
- Evidence schema `bitcoin-rs-core-differential-v2` is verified by
  `crates/p2p/tests/core_interop_live.rs`.
- This complements `kernel_block_parity` / `kernel_vector_parity`: those
  tests the C++ engine in-process; this tests a running Core node.

### `CORE-03`: BIP152 compact-block relay against live Core

- **Owner**: `scripts/run-p2p-core-interop.sh` phases A–C plus the raw
  BIP152 probe; verified by `assert_bip152_relay` in
  `crates/p2p/tests/core_interop_live.rs`.
- Phase A mines coinbase-only blocks through `generateblock` templates:
  every near-tip compact fetch reconstructs fully with no `getblocktxn`.
- Phases B and C mine blocks over seeded mempool transactions (seeded
  before bitcoin-rs connects, so the node never learns them): a three-tx
  block recovers via `getblocktxn`/`blocktxn`, and a 130-tx block exceeds
  the bounded missing list and falls back to one full-block `getdata`.
- Near-tip latency and bandwidth are recorded per phase and separated
  from the IBD round in the evidence `performance` section.
- A raw scripted peer proves the serving side: `getdata(MSG_CMPCT_BLOCK)`
  is answered with a `cmpctblock` whose header hashes to the tip, a valid
  `getblocktxn` returns a `blocktxn`, and out-of-range indexes end the
  connection.

## Proven by

- Main workflow `core-differential`.
- `cargo test -p bitcoin-rs-p2p --test core_interop_live -- --ignored`
  with `P2P_CORE_INTEROP_EVIDENCE` set by the driver.
