# Bitcoin Core differential contract

libbitcoinkernel oracle tests prove consensus-script parity. This page
owns live Bitcoin Core node comparisons: observable chain identity after a
real P2P sync and curated acceptance through public RPCs. The reference is
a running pinned binary, not a replay of captured JSON.

## Clauses

### `CORE-01`: Pinned Core 31.1 bitcoind

- **Owner**: `scripts/install-bitcoind.sh`.
- The live lane downloads the host platform's Bitcoin Core 31.1 release
  from bitcoincore.org — `bitcoin-31.1-x86_64-linux-gnu.tar.gz` on Linux,
  `bitcoin-31.1-win64.zip` under MSYS/MINGW/CYGWIN on Windows — and checks
  the archive SHA-256 before extracting `bitcoind` (`bitcoind.exe`).
- A cached prefix is reused only when its stamp matches that SHA-256 and
  `bitcoind -version` completes successfully and reports `v31.1`.

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

### `CORE-04`: Curated live block and transaction acceptance

- **Owner**: `e2e/tests/acceptance.rs`, using `e2e::differential` and
  `ProcessNode`; no production validation hooks or second process harness.
- Both isolated regtest nodes receive the same 500 Core-mined funding
  blocks, crossing both nodes' CSV/BIP34 activation thresholds before
  comparison. Setup evidence records Core deployment and candidate template
  observations. Every candidate starts at a checked common height and tip with
  empty mempools and no peer connections. Blocks must extend that tip.
- The same serialized input is sent to both `submitblock` or both
  `testmempoolaccept` calls. Accept/reject disagreements fail the test;
  reject-reason strings are retained without asserting their equality.
  Each case also requires the reference's expected accept/reject result.
- Block cases cover a Core coinbase-only block, bad merkle root, multiple
  coinbase transactions, short coinbase scriptSig, excessive coinbase
  value, incorrect BIP34 height, and timestamp equal to MTP. A final
  Core-produced block spends the mature funding coin after all rejections.
- Transaction previews cover a valid mature spend, immature coinbase,
  duplicate inputs, overspend, output above the money range, missing input,
  and an unsatisfied BIP68 relative height lock. Signatures are regenerated
  after input/output changes so they do not introduce an unrelated fault.
- `bad-prevblk`, `prev-blk-not-found`, `duplicate*`, `inconclusive*`, malformed
  replies, RPC/transport errors, and unexpected state changes are harness
  failures. They never count as matched consensus rejections. Previews and
  rejected blocks leave the common public state unchanged; accepted blocks
  advance both nodes to the candidate hash.
- Each `acceptance-*.json` under the candidate's process evidence directory
  records input bytes and identity, expected verdict, replies and checked
  states when observed, classification, and links to both process evidence
  directories.
  The initial input record is written before submission and retained even
  when a later check fails. Existing process evidence contains pinned binary
  identities, launch arguments, RPC transcripts, and output logs.
- This is a bounded curated suite. Coverage-guided live Core fuzzing and
  broader rule-family coverage remain follow-up work under #1323.

## Proven by

- Main workflow `core-differential`.
- The workflow retains any generated evidence JSON, installer/build/driver
  output, and node logs in the `core-differential-<run_attempt>` artifact for
  seven days, including failed runs. Node databases and RPC cookies are
  excluded. Failures before evidence generation can leave only partial logs;
  failures before log creation can leave no files to upload.
- `cargo test -p bitcoin-rs-p2p --test core_interop_live -- --ignored`
  with `P2P_CORE_INTEROP_EVIDENCE` set by the driver.
- `cargo test --locked -p bitcoin-rs-e2e --test acceptance`, after building
  the daemon and provisioning the pinned Core fixture. `BITCOIN_RS_NODE`
  and `BITCOIN_RS_REFERENCE_BITCOIND` can name the exact binaries.
- The existing `ci.yml` `test-workspace` lane discovers the acceptance test
  on merge-queue and main runs; its always-run process-evidence upload
  preserves the case JSON and both processes' logs on success or failure.
