# P2P wire contract (pointer)

The peer-wire contract lives in
[docs/policies/p2p-compatibility.md](../policies/p2p-compatibility.md). That
document is the owner: it pins Bitcoin Core 31.1, declares the transport
envelope, the handshake fields, the 36-command message surface, the
reject-or-ignore policy, and the deviation ledger. This page adds nothing
normative; it places the policy under the
[contracts precedence rule](README.md).

## Clauses

### `P2P-01`: Protocol wire framing and handshake compatibility

- **Owner**: `docs/policies/p2p-compatibility.md` owns the P2P wire specification,
  pinning Bitcoin Core 31.1.
- **Scope**: `crates/p2p` wire, handshake, protocol FSM, and message policy; the
  chain-serving query `crates/p2p/src/chain_query.rs`; and node network flags.
- Message framing, 36-command envelope decoder, service flags, network magic,
  and reject-or-ignore semantics follow the policy document.

### `P2P-02`: Connection lifecycle and peer lease ownership

- Peer connection sessions and `PeerLease` lifecycle are owned by `crates/p2p`.
- The node-side synchronization coordinator consumes peer lifecycle events
  without duplicating connection replacement or cancellation rules.

## Live gaps

- **Peer lifecycle boundary**: Moving the remaining P2P scheduling and lifecycle policy out of `crates/node` is tracked under #217 (open).

## Proven by

- `crates/p2p/tests/core_compat.rs`:
  - `cargo test -p bitcoin-rs-p2p --test core_compat` pins handshake fields,
    per-network framing, relay round-trips, the reject-or-ignore matrix, and
    peer-visible reorg/restart behavior.
- `crates/p2p/tests/core_interop_live.rs`: live interop lane running via
  `scripts/run-p2p-core-interop.sh` when an external `bitcoind` is provided.
