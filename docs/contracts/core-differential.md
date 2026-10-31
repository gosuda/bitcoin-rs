# Bitcoin Core differential contract

libbitcoinkernel oracle tests prove consensus-script parity. This page owns live Bitcoin Core node comparisons: observable chain identity after a real P2P sync and curated acceptance through public RPCs. The reference is a running pinned binary, not a replay of captured JSON.

## Clauses

### `CORE-01`: Pinned Core 31.1 bitcoind

- **Owner**: `scripts/install-bitcoind.sh` (`install-bitcoind.ps1` on Windows).
- The live lane downloads the Bitcoin Core 31.1 artifact for the host platform (`x86_64-linux-gnu`, `arm64-apple-darwin`, or `win64`) from bitcoincore.org.
- The lane checks the archive SHA-256 pinned for that platform in `core-compat.toml` before extracting `bitcoind` (`bitcoind.exe` on Windows).
- The bash script serves POSIX shells; `install-bitcoind.ps1` serves native PowerShell.
- The harness reuses a cached prefix only when its stamp matches that SHA-256 hash.
- The check MUST also verify that `bitcoind -version` completes successfully and reports `v31.1`.

### `CORE-02`: Observable chain identity matches after P2P sync

- **Owner**: `scripts/run-p2p-core-interop.sh`.
- After bitcoin-rs catches up to Core on regtest, `getblockcount`, `getbestblockhash`, and `getblockchaininfo.{chain,blocks}` agree.
- Evidence schema `bitcoin-rs-core-differential-v4` is verified by `crates/p2p/tests/core_interop_live.rs`.
- This test complements `kernel_block_parity` / `kernel_vector_parity`.
- Those tests check the C++ engine in-process.
- This test checks a running Core node.

### `CORE-03`: BIP152 compact-block relay against live Core

- **Owner**: `scripts/run-p2p-core-interop.sh` phases A–C plus the raw BIP152 probe; verified by `assert_bip152_relay` in `crates/p2p/tests/core_interop_live.rs`.
- Phase A mines coinbase-only blocks through `generateblock` templates.
- Every near-tip compact fetch reconstructs fully with no `getblocktxn`.
- Phases B and C mine blocks over seeded mempool transactions (seeded before bitcoin-rs connects, so the node never learns them).
- A three-tx block recovers via `getblocktxn`/`blocktxn`.
- A 130-tx block exceeds the bounded missing list and falls back to one full-block `getdata`.
- Near-tip latency and bandwidth are recorded per phase and separated from the IBD round in the evidence `performance` section.
- A raw scripted peer proves the serving side.
- The node answers `getdata(MSG_CMPCT_BLOCK)` with a `cmpctblock` whose header hashes to the tip.
- A valid `getblocktxn` returns a `blocktxn`, and out-of-range indexes end the connection.

### `CORE-05`: Proactive block announcements across a live reorg

- **Owner**: `scripts/p2p_block_announcement_probe.py`, invoked by `scripts/run-p2p-core-interop.sh`; verified by `assert_block_announcements` in `crates/p2p/tests/core_interop_live.rs`.
- Equivalent scripted peers connect to pinned Core 31.1 and bitcoin-rs.
- One peer requests no announcement extension.
- One peer negotiates BIP130 `sendheaders`.
- One peer negotiates BIP152 v2 high-bandwidth relay.
- Each peer demonstrates the same current parent header before Core mines the block.
- The probe requires both nodes to emit, respectively, `inv`, `headers`, and unsolicited `cmpctblock` frames naming the newly accepted tip.
- Core then invalidates that block and mines a two-block competing branch.
- Both nodes MUST announce the replacement tip using the same negotiated mechanisms.
- Neither node MAY re-announce the abandoned hash after the reorg begins.
- The probe keeps each peer open for a bounded observation window after the replacement tip arrives.
- A later stale announcement still fails the run.
- This is a main-only qualification lane.
- Its presence and PR-CI compilation do not by themselves constitute recorded external evidence.
- The ecosystem matrix MAY upgrade CORE-05 only after the main workflow retains a successful evidence artifact for the merged implementation.

### `CORE-06`: BIP324 v2 transport against live Core

- **Owner**: `scripts/run-p2p-core-interop.sh`, with Core started as `-v2transport=1`; verified by `assert_transports` in `crates/p2p/tests/core_interop_live.rs`.
- The main bitcoin-rs node keeps `--v2transport=false`, so CORE-02, CORE-03 and its connection to Core stay v1 evidence.
- Its leg MUST report `v1` with empty session ids on both ends.
- A fresh bitcoin-rs node with `--v2transport=true` dials Core.
- Core dials (`addnode … onetry true`) another fresh node with `--v2transport=true` and no other peer.
- Each node syncs the whole chain of Core over that v2 connection.
- For each connection the evidence records both ends' `getpeerinfo` `transport_protocol_type`, `session_id` and direction.
- Both v2 legs MUST report `v2` on both ends with the same 32-byte session id.
- Each leg MUST answer a `ping` Core sends after the sync with a `pong`.
- A third fresh node with `--v2transport=false` dials Core and syncs the same chain.
- The evidence `ibd_cost` records Core's `bytessent` and `bytesrecv` for it and for the v2 dialer as each reaches Core's tip.
- This measurement records the bandwidth cost of v2 rather than bounding it.
- The best block hash of the v2-off node is recorded with it and MUST equal Core's.
- Like CORE-05, this is a main-only qualification lane: the recorded evidence artifact, not the lane's presence, is what qualifies BIP324 interop.

### `CORE-04`: Curated live block and transaction acceptance

- **Owner**: `e2e/tests/acceptance.rs`, using `e2e::differential` and `ProcessNode`; no production validation hooks or second process harness.
- Both isolated regtest nodes receive the same 500 Core-mined funding blocks, crossing both nodes' CSV/BIP34 activation thresholds before comparison.
- Setup evidence records Core deployment and candidate template observations.
- Every candidate starts at a checked common height and tip with empty mempools and no peer connections.
- Blocks MUST extend that tip.
- The same serialized input is sent to both `submitblock` or both `testmempoolaccept` calls.
- Accept/reject disagreements fail the test.
- Reject-reason strings are retained without asserting their equality.
- Each case also requires the reference's expected accept/reject result.
- Block cases cover a Core coinbase-only block, bad merkle root, and multiple coinbase transactions.
- Block cases also cover short coinbase scriptSig, excessive coinbase value, and incorrect BIP34 height.
- Block cases also cover timestamp equal to MTP, and a max-version (0xFFFFFFFF) BIP68 spend with an unmet relative lock.
- A final Core-produced block spends the mature funding coin after all rejections.
- Transaction previews cover a valid mature spend, immature coinbase, and duplicate inputs.
- Transaction previews also cover overspend, output above the money range, and missing input.
- Transaction previews also cover an unsatisfied BIP68 relative height lock.
- Signatures are regenerated after input/output changes so they do not introduce an unrelated fault.
- `bad-prevblk`, `prev-blk-not-found`, `duplicate*`, `inconclusive*`, malformed replies, RPC/transport errors, and unexpected state changes are harness failures.
- They never count as matched consensus rejections.
- Previews and rejected blocks leave the common public state unchanged.
- Accepted blocks advance both nodes to the candidate hash.
- Each `acceptance-*.json` under the candidate's process evidence directory records input bytes and identity.
- It also records expected verdict, replies and checked states when observed, classification, and links to both process evidence directories.
- The initial input record is written before submission and retained even when a later check fails.
- Existing process evidence contains pinned binary identities, launch arguments, RPC transcripts, and output logs.
- This is a bounded curated suite. Coverage-guided live Core fuzzing and broader rule-family coverage remain follow-up work under #1323.

## Verification boundaries

The binary process harness owns real Core comparisons over RPC, P2P announcements, reorgs, and negotiated transport. Shared fixture/custody checks validate inputs; they do not replace a provisioned process run or close the clause-local gaps. The configured CI/evidence lanes own execution results.
