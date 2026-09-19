# Solutions

Non-normative: historical decisions, evidence, and failed approaches. Informative, not normative. For current contracts see `docs/contracts/`.

Each note records the state of the code and the measurements at its date. Where a note quotes constants, paths, or benchmark numbers, read them as evidence from that time and check the cited source before relying on them.

## Architecture patterns

- [Node-level reorg execution](architecture-patterns/node-reorg-execution-design.md) (2026-08-08) — where the disconnect commit point sits, why undo records are not idempotent, and how derived TxIndex watermarks stay outside the authoritative rollback.
- [P2P owns the peer lifecycle](architecture-patterns/p2p-owns-peer-lifecycle.md) — one `PeerTable` as the connection authority; `PeerSource` identity so a stale predecessor cannot publish, send, or cancel a same-address replacement.
