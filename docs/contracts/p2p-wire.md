# P2P wire contract

The decoded command inventory belongs to `crates/p2p/src/compat.rs`.
[The compatibility policy](../policies/p2p-compatibility.md) owns handshake
fields, reject-or-ignore behavior, and current deviations. Planned clauses
below do not change that inventory or establish implemented support.

### `P2P-01`: Wire inventory and framing

v1 envelopes, payload bounds, service flags, and network magic follow the
checked inventory. Unknown commands are ignored after readiness; before
readiness, non-handshake traffic disconnects. Oversized payloads disconnect.
`core_compat`, `wire_codec`, and `handshake_roundtrip` test these boundaries.

### `P2P-02`: Scheduling and session ownership

`P2pService` owns sessions; `PeerTable` and `PeerLease` own session identity.
Today `BlockSyncDownloadWindow` in `crates/node/src/sync.rs` owns download
scheduling. Moving that window into P2P is a target, not a completed change.
The target has one scheduler, exact disconnect requeue, stale-session rejection,
byte-bounded buffers, and control traffic that cannot be starved by bulk traffic.
The planned `overhaul_download_owner` suite does not yet prove those targets.

### `P2P-03`: Identity-checked monotonic height credit

Only the delivering connection earns credit for validated header evidence.
Credit is monotonic and retained branch evidence survives peer loss and chain
selection changes. Reconnecting at the same address is a new session. This
clause retains the ID used by the existing peer and node tests; discovery does
not reuse it.

Evidence: `peer_table.rs` tests
`note_announced_height_credits_only_the_delivering_connection` and
`note_announced_height_raises_monotonically_and_reports_actual_updates`;
`sync.rs` tests `tick_fetches_new_tip_headers_from_at_tip_peers`,
`tick_fetches_reorg_fork_announced_by_at_tip_peer`,
`losing_fork_credit_survives_winner_disconnect`, and
`cold_start_stall_hedges_front_without_reassigning_owner`.

### `P2P-04`: Compact blocks (target)

Compact-block messages are decoded and ignored today. No production
`compact_block.rs` owner exists. Future BIP152 reconstruction must verify full
transaction identities after short-ID matching, handle collisions and missing
transactions with a full-block fallback, and use ordinary block validation.
No partial reconstruction may commit or retain stale request leases.
`overhaul_compact_blocks` remains a planned suite, not current evidence.

### `P2P-05`: v2 transport and compact filters (target)

Only v1 transport is implemented. There is no `bip324` Cargo feature, pinned
BIP324 dependency, or `transport_v2.rs`. Future authenticated transport must
not silently downgrade after authentication failure. Compact-filter messages
are decoded and ignored, and the capability is not advertised. Future serving
must use precomputed index-owned bytes and advertise only retained capabilities.
`overhaul_optional_protocols` is planned and cannot currently be run.

### `P2P-06`: Persistent discovery (target)

`getaddr`, `addr`, and `addrv2` are decoded and ignored today. A bounded,
versioned address manager with tried/new tables, validated intake, restart
persistence, and explicit corrupt-state reseeding is a target. No
`address_book.rs` owner exists. Discovery recovery must never reset authoritative
chainstate. `overhaul_peer_contract` is planned, not proof of discovery support.

## Existing verification

`cargo test -p bitcoin-rs-p2p --test core_compat` checks the command inventory
and current wire behavior. The live `core_interop_live` lane is environment-gated;
it must not be reported as run without its Core process and recorded evidence.
