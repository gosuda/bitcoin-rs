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
