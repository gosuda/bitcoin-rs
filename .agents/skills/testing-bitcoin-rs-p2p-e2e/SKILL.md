---
name: testing-bitcoin-rs-p2p-e2e
description: How to run real end-to-end P2P sync tests for bitcoin-rs without the pinned x86_64 bitcoind (macOS or Linux) — spawn the daemon via the bin/bitcoin-rs test harness and drive it with a loopback wire-protocol fake peer, in either connection direction.
---

# Testing bitcoin-rs P2P sync end-to-end

## When this applies
The `overhaul_process_*` / `overhaul_reference_set` lanes in `bin/bitcoin-rs/tests` exec a pinned **x86_64-linux** `bitcoind` at `target/reference-core-31.1/` and cannot run on macOS. You can still exercise the real daemon end-to-end (inv/headers → getdata → bodies → apply/reorg) with a fake wire-protocol peer over loopback — on Linux too.

## Environment
- Linux (this box): `cargo` IS on PATH (`~/.cargo/bin`). A debug daemon binary is usually already built at `target/debug/bitcoin-rs`; rebuild portable with `cargo build --bin bitcoin-rs --no-default-features --features fjall`.
- macOS (the original box this skill was written for): Rust toolchain is NOT on PATH: `export PATH="/Users/devin/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"`.

## Harness pattern
Create a **temporary** integration test `bin/bitcoin-rs/tests/<name>.rs` with `mod support;` (reuses the checked-in harness crate: `support::process_node`, `support::process_peer`, `support::process_node::NodeBinary`, `HarnessError`).

- `ProcessNode::start(NodeBinary::BitcoinRs)` writes `node.toml` (regtest, `p2p_listen` loopback, `dns_seeds_enabled=false`), spawns `CARGO_BIN_EXE_bitcoin-rs` with `--storage-backend fjall --rpc-user parity --rpc-password parity --dbcache-mb 64`, waits on `getblockchaininfo`. Evidence lands in `target/process-harness/run-*/` (`stderr.log`, `transcript.jsonl`, `launch.json`, `stdout.log`). RPC on `node.rpc_addr` with basic auth `parity:parity`; P2P on `node.p2p_addr`.
- Implemented RPCs (crates/rpc/src/registry.rs): `getblockcount`, `getbestblockhash`, `getpeerinfo`, `getconnectioncount`, `getblockchaininfo`, `submitblock`, `generatetoaddress` (Status::ImplementedUnverified, registry.rs:143). `generatetoaddress` mints valid regtest blocks through the mining coordinator; hand-rolled blocks (recipe below) are still needed for the witness-commitment discriminator — the RPC-minted coinbase does not carry the crafted witness nonce the strip/serve assertions discriminate on.
- Implement a `LivePeer` wire client on `TcpStream` (pattern from `support/process_peer.rs`, which has private send/recv — copy or reimplement): send `version` (70016, `ServiceFlags::WITNESS`, services_witness), answer version/verack/`wtxidrelay`, then `sendheaders` mode. Journal every frame to disk for evidence.
- Frame decoding caps: `ProcessPeer`'s read helper caps payloads at 4,000,000 bytes — the wire protocol's `MAX_MESSAGE_PAYLOAD` is 32 MiB and a `block` payload can approach ~4M weight units serialized, at/over the harness cap (`headers` replies are bounded at `MAX_HEADERS_RESPONSE` = 2,000 entries ≈ 160 KB and are not the concern). Use your own reader with a ≥32 MiB cap.
- `recv()` must distinguish **soft** errors (`WouldBlock`/`TimedOut`/`deadline` — peer stays alive, keep pumping) from **hard** errors (truncated frame, checksum, protocol violation — mark the peer dropped). Treating soft timeouts as drops made the test harness deaf and was the cause of two false failures.

## Building valid regtest blocks (no bitcoind)
Recipe proven in `crates/node/tests/sync_smoke.rs`:
- Clone the parent block's coinbase tx, rewrite the height push in `script_sig`, recompute `merkle_root`, grind `nonce` until `bitcoin::Target::from_compact(bits).is_met_by(hash)` (bits 0x207fffff ≈ 1-in-2 per nonce). Do NOT hand-roll endian comparisons — `is_met_by` handles them.
- For segwit blocks: coinbase `input[0].witness = Witness::from_slice(&[reserved32])`, plus an `OP_RETURN` output with script_pubkey `[0x6a,0x24,0xaa,0x21,0xa9,0xed] || sha256d(witness_root || reserved)` (see `check_block_body_binding` in crates/consensus/src/verify_block.rs). A witness-stripped body then fails binding as `WitnessNonceSize` — exactly what you want for discriminating tests.
- Serving "faithfully": `WitnessBlock`/`CompactBlock` getdata → full body; plain `Block` getdata → strip all input witnesses (real Core behavior).

## Driving the OUTBOUND direction too (both directions on one node)
- To make the node dial a fake peer (covers `run_outbound_handshake`/`send_handshake_message` + outbound writer loop): pre-bind a `TcpListener` on `127.0.0.1:0`, convert its address to a string (`let addr = listener.local_addr()?.to_string()`), then `ProcessNode::start_with_options(NodeBinary::BitcoinRs, &["--connect", &addr], START_TIMEOUT)` — `start_with_options` takes `&[&str]`, so `&SocketAddr` does not compile. `connect` becomes `fixed_peers` → `run_fixed_peer_bootstrap` pushes it to the outbound-drain worker, which dials within ~1 s. `accept()` with a nonblocking poll loop (30 s) catches it.
- To make the node dial YOU (inbound for the node): `connect_loopback(node.p2p_addr, deadline)` as usual.
- `getpeerinfo` exposes `inbound: bool` — assert one `true` + one `false` to prove both directions registered.
- Observed on a `--connect` outbound conn: the node sends `wtxidrelay`/`sendaddrv2`/`sendheaders` TWICE — once upfront in `handshake::start()` and again in `dispatch_inbound`'s reply to our `version` (dispatch.rs:182). Pre-existing message selection, not a wire-encoding issue.
- Node serves `getdata` for applied blocks with `block` frames on BOTH directions (the `outbound production gate` in dispatch.rs is a write-budget headroom check, not a sync gate).

## Node behaviors worth knowing (observed live)
- `SYNC_TICK` = 1s; inv-echo `getdata` is emitted synchronously on the connection (observed 0 ms after `inv`).
- Windowed `getdata` uses `Inventory::WitnessBlock` (type `0x40000002`); a plain `Block` request is type `0x2`.
- The node aggressively re-sends `getheaders` when the peer keeps answering with already-known headers (~50 probes in <10 ms observed). Filter this ping-pong out of logs; also drain it in `pump` so your `getdata` observations aren't buried.
- A `headers` batch arriving before the node has bootstrapped its header tree (or for a parent it hasn't seen) is rejected with `missing parent header …` WARN in stderr — resend/headers-reannounce recovers; not necessarily a bug.
- A `block` body whose hash is in the tree but has no pending getdata (peer disconnect released it, inv-race, cold-front hedge) takes the `needs_height_lookup` untracked path — push it from a *second* peer after dropping the first to hit this deterministically.
- `getconnectioncount` reflects inbound peers; inbound peers ARE eligible for body requests once they demonstrate a better tip (`note_announced_tip` on accepted headers).
- Check daemon health by grepping `target/process-harness/run-*/stderr.log` for `panic` / `PrevHashMismatch`; a correct run logs only lsm-tree ingest INFO + startup lines.
