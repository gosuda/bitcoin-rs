# External API contract (pointer)

The external-API contract is declared in code, not prose. This page adds
nothing normative; it places the owners under the
[contracts precedence rule](README.md).

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

- **Owner**: `MiningControl::generate` in `crates/rpc/src/context.rs`,
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
  ranged/multipath descriptors are refused), requires the transactions array
  (an explicit `[]` is coinbase-only), keeps listed order, does not add those
  fees to the coinbase, treats 64-character hex as a mempool txid, and includes
  decoded raw transactions without requiring mempool admission.

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
  `generateblock_requires_transactions_array`, `generateblock_keeps_raw_transactions`
- `crates/node/tests/mining.rs` tests `generate_mines_coinbase_only_blocks_to_the_tip`,
  `generateblock_rejects_unknown_mempool_txid`,
  `generateblock_raw_tx_does_not_require_mempool_admission`,
  `generate_without_submit_does_not_advance_the_tip`
- `crates/mining/tests/template_shape.rs` tests `candidate_solves_an_unsolved_regtest_header`,
  `ordered_assembly_keeps_snapshot_order`
