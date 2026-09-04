# External API contract (pointer)

`API-01`–`API-04` place owners under the
[contracts precedence rule](README.md). `API-05` is the solo-mining generate
path. `API-06` is `getnetworkhashps` snapshot consistency. `API-07` is the RPC
transport socket policy.

## Clauses

### `API-01`: Single manifest dispatcher authority

- **Owner**: `MANIFEST` in `crates/rpc/src/manifest.rs` is the single source of
  truth for RPC, REST, and ZMQ external interfaces.
- A JSON-RPC method answers only when a non-`Unimplemented` row carries its
  name. Rows cover JSON-RPC, REST prefixes, and ZMQ topics, each with a status
  (`Implemented`, `Deviation`, `Extension`, `Unimplemented`) declared against
  Bitcoin Core 31.x.
- Methods marked `Unimplemented` return `RpcError::MethodNotFound` (code `-32601`).

### `API-02`: Generated reference synchronization

- [docs/rpc-reference.md](../rpc-reference.md) is a generated file rendered
  directly from `MANIFEST`. It must not be edited by hand.
- Regenerate with:
  `REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage -- --ignored regenerate_reference`
- `crates/rpc/tests/manifest_coverage.rs` enforces that the checked-in reference
  matches the code manifest exactly on every CI run.

### `API-03`: Error code mappings and wallet-free surface

- JSON-RPC failures map through `RpcError` (`crates/rpc/src/error.rs`):
  standard JSON-RPC codes (`-32700`, `-32600`..=`-32603`) and Core codes `-3`
  (invalid type) and `-5` (not found).
- The node ships no wallet and holds no private key material. Methods that
  would reveal, import, create, or use private keys return
  `RpcError::MethodNotFound`. PSBT combination/finalization and descriptor
  utilities remain supported as they operate without private keys.

### `API-04`: Read consistency and query budgeting

- Multi-record queries across chainstate use optimistic tip fencing or
  active-tip verification against `BlockTree`. If a reorg occurs during
  assembly, queries return `503 Service Unavailable` rather than inconsistent
  data.
- Statistical and script index queries are bounded by `QueryBudget` to prevent
  memory exhaustion.

### `API-05`: Solo-mining generate path

- **Owner**: `MiningControl::generate` in `crates/mining/src/control.rs`,
  implemented by `MiningCoordinator::generate_blocks` in
  `crates/node/src/mining.rs`.
- The operation assembles a fresh candidate (no GBT cache), solves it, then
  either submits through `Chainstate::apply_block` or dry-validates through
  `Chainstate::validate_block` (`ARCH-07`). Persistence and tip advancement
  are conditional on `submit`; validation is not.
- Each submitted block is a separate commit. An error after *N* successful
  submissions leaves those *N* blocks durable. Callers own retry after reading
  the applied tip. `nblocks` is not capped; the result vector grows one block
  at a time.
- `generatetoaddress` accepts only a network-valid address, uses mempool
  package selection, collects fees, and always submits.
- `generateblock` accepts an address or descriptor (`require_checksum = false`;
  a supplied checksum is verified). Ranged/multipath descriptors are refused.
  The transactions array is required (an explicit `[]` is coinbase-only).
  Listed order is kept, those fees are not added to the coinbase, 64-character
  hex is a mempool txid, and decoded raw transactions are included without
  mempool admission. Extra positional arguments are rejected.

### `API-06`: `getnetworkhashps` snapshot and invalid-height behavior

- **Owner**: `MiningCoordinator::network_hash_ps` in `crates/node/src/mining.rs`.
  Height resolution has one owner: `resolve_hash_ps_start`.
- The method takes the block-tree read lock, then loads one applied-tip
  snapshot. Height checks and the hash-rate walk use that snapshot and that
  locked tree, not a second tip load.
- `nblocks` (`lookup`) must be a positive count or `-1` (since the last
  difficulty retarget). Otherwise the RPC is Core `-8`
  (`RpcError::InvalidParameter`) with
  `"Invalid nblocks. Must be a positive number or -1."`
- `height` must be `-1` (the snapshot tip) or an existing applied-chain height
  on that snapshot. Heights below `-1`, above the snapshot tip, or in range
  but unwalkable from that tip, are Core `-8` with
  `"Block does not exist at specified height"`, not a zero hash-rate.
- An empty chain with `height == -1` estimates `0.0`.
- `getmininginfo`'s `networkhashps` is best-effort from the applied tip and
  does not use this RPC height-validation error path.

### `API-07`: RPC transport disables Nagle

- RPC HTTP connections configure `TCP_NODELAY` before serving requests. This
  transport policy applies to both client and server sides of the accepted RPC
  stream.

The wallet-facing subset of this surface — tip, fees, address/script
queries, and broadcast over Esplora, plus the key-free node RPCs — is
owned by [wallet-facing.md](wallet-facing.md).

## Live gaps

- **Full Core differential suite**: Versioned Core response structs, golden fixtures, and differential test lanes across all RPC methods are tracked under #78 (open).
- **Typed embedding surface**: Direct in-process application API as an alternative to localhost JSON-RPC daemon boundary is tracked under #145 (open).

## Proven by

- `crates/rpc/tests/manifest_coverage.rs`:
  - `rpc_rows_and_the_live_registry_agree_both_ways`
  - `rest_rows_and_router_registrations_agree_both_ways`
  - `zmq_rows_are_valid_core_topics`
  - `every_unimplemented_rpc_row_answers_method_not_found`
  - `generated_reference_matches_checked_in`
- `crates/rpc/src/handlers/mining.rs` tests `generatetoaddress_projects_solved_hashes`,
  `generatetoaddress_rejects_script_hex_and_descriptors`,
  `generateblock_projects_hash_object`, `generateblock_accepts_addr_descriptor`,
  `generateblock_without_submit_includes_hex`,
  `generateblock_requires_transactions_array`, `generateblock_keeps_raw_transactions`,
  `generateblock_rejects_trailing_parameters`,
  `generateblock_rejects_invalid_supplied_checksums`
- `crates/node/tests/mining.rs` tests `generate_mines_coinbase_only_blocks_to_the_tip`,
  `generateblock_rejects_unknown_mempool_txid`,
  `generateblock_raw_tx_does_not_require_mempool_admission`,
  `generate_without_submit_does_not_advance_the_tip`
- `crates/mining/tests/template_shape.rs` tests `candidate_solves_an_unsolved_regtest_header`,
  `ordered_assembly_keeps_snapshot_order`
- `API-06`:
  - `crates/node/src/mining.rs` test `hash_ps_at_rejects_a_height_the_tip_cannot_resolve`
  - `crates/node/tests/mining.rs` test `network_hash_ps_rejects_core_invalid_windows`
  - `crates/rpc/src/handlers/mining.rs` test `getnetworkhashps_projects_control_invalid_request_as_invalid_parameter`
