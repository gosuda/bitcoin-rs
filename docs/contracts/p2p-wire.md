# P2P wire contract (pointer)

The peer-wire contract is split across two owners. This page adds nothing
normative; it places them under the
[contracts precedence rule](README.md).

- [`crates/p2p/src/compat.rs`](../../crates/p2p/src/compat.rs) owns the
  decoded command inventory and the pinned Core version.
- [docs/policies/p2p-compatibility.md](../policies/p2p-compatibility.md)
  owns the handshake fields, reject-or-ignore matrix, deviation ledger,
  and verification process. The §5 table is a checked projection of
  `COMMANDS`.

## Clauses

### `P2P-01`: Protocol wire framing and handshake compatibility

- **Owner**: `crates/p2p/src/compat.rs` owns the 36-command inventory and
  `PINNED_CORE_VERSION` (Bitcoin Core 31.1). The policy document owns
  handshake fields, reject-or-ignore semantics, and recorded deviations.
- **Scope**: `crates/p2p` wire, handshake, protocol FSM, and message policy; the
  chain-serving query `crates/p2p/src/chain_query.rs`; and node network flags.
- Message framing, envelope decoder, service flags, and network magic follow
  the inventory and the policy document. v1 frames for handshake and inventory
  commands are byte-identical to rust-bitcoin's `RawNetworkMessage`.

### `P2P-02`: Connection lifecycle and peer lease ownership

- Peer connection sessions and `PeerLease` lifecycle are owned by `crates/p2p`.
- The node-side synchronization coordinator consumes peer lifecycle events
  without duplicating connection replacement or cancellation rules.

### `P2P-03`: Peer socket transport policy

- Peer sockets use blocking I/O, `TCP_NODELAY`, a one-second read poll
  interval, and a 60-second write timeout for the handshake and stalled-peer
  ceiling. Inbound and outbound streams receive the same policy.

### `P2P-04`: Coalesced vectored-write accounting

- Peer message writes preserve the header/payload vectored write through the
  counting stream, and account for every byte accepted by the inner writer.

## Live gaps

- **Peer lifecycle boundary**: Moving the remaining P2P scheduling and lifecycle policy out of `crates/node` is tracked under #217 (open).

## Proven by

- `crates/p2p/tests/core_compat.rs`:
  - `cargo test -p bitcoin-rs-p2p --test core_compat` pins the command
    inventory against the policy table, rust-bitcoin v1 envelopes, handshake
    fields, per-network framing, relay round-trips, the reject-or-ignore
    matrix, and peer-visible reorg/restart behavior.
- `crates/p2p/tests/core_interop_live.rs`: live interop lane running via
  `scripts/run-p2p-core-interop.sh` when an external `bitcoind` is provided.
