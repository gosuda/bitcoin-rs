# External API contract (pointer)

`API-01`–`API-04` place owners under the
[contracts precedence rule](README.md). `API-05` is the solo-mining generate
path. `API-06` is `getnetworkhashps` snapshot consistency. `API-07` is the
BIP22/BIP23 `getblocktemplate` extras the pinned corepc type does not model.
`API-08` is mainnet template operational gates. `API-09` is `submitheader`.
`API-10` is GBT client-rule negotiation. `API-11` is `submitblock` decode.
`API-12` is GBT proposal request parsing.

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
  (invalid type), `-5` (not found), `-8` (invalid parameter), `-9` (not
  connected), `-10` (initial download), `-22` (deserialization), `-25`
  (verify error), and `-26` (verify rejected).
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

### `API-07`: BIP22/BIP23 template extras

- **Owner**: `MiningCoordinator::template_from_candidate` in
  `crates/node/src/mining.rs`; JSON projection in
  `crates/rpc/src/handlers/mining.rs` `render_block_template`.
- Capabilities are the producer’s implemented set (`proposal`, `longpoll`).
  Client-advertised names are not echoed.
- `submitold` is present after a long-poll wait and omitted otherwise. `workid`
  is not emitted.
- On signet, the template carries `signet` in `rules` (mandatory) and
  `signet_challenge`. Other networks omit `signet_challenge`.

### `API-08`: Mainnet template operational gates

- **Owner**: `ensure_template_ready` in `crates/rpc/src/handlers/mining.rs`.
- Template mode on mainnet requires at least one live peer (`PeerTable`) and
  that the node has left IBD (`Context::is_initial_block_download`). Failures
  are Core `-9` (`bitcoin-rs is not connected!`) and `-10`
  (`bitcoin-rs is in initial sync and waiting for blocks...`).
- Proposal mode does not apply these gates. Networks other than mainnet skip
  them, matching Core `IsTestChain()`.

### `API-09`: `submitheader`

- **Owner**: `MiningCoordinator::submit_header` in `crates/node/src/mining.rs`.
  RPC decodes the hex and projects the result; it does not admit headers.
- Decode failures (invalid hex, fewer than 80 bytes) are Core `-22`
  (`Block header decode failed`). Extra bytes after an 80-byte header are
  ignored, matching Core `DecodeHexBlockHeader`.
- The previous header must already be in the block tree. Otherwise the RPC
  returns `-25` (`Must submit previous header (HASH) first`).
- Admission uses `accept_headers`, the same consensus gate as inbound P2P
  headers. Duplicates succeed. Invalid headers return `-25` with Core reject
  reasons (`high-hash`, `bad-diffbits`, `time-too-old`, `time-too-new`).
- Success is JSON `null`. Header-only admission does not apply the block or
  publish a mining generation.

### `API-10`: GBT client-rule negotiation

- **Owner**: `ensure_client_rules_for_template` and
  `ensure_client_supports_mandatory_rules` in
  `crates/rpc/src/handlers/mining.rs`.
- Template mode requires the client to list `segwit`. On signet it also
  requires `signet`. Failures are Core `-8` with Core's exact messages:
  `getblocktemplate must be called with the segwit rule set (call with {"rules": ["segwit"]})`
  and
  `getblocktemplate must be called with the signet rule set (call with {"rules": ["segwit", "signet"]})`.
  Signet is checked first, matching Core v31.0 `src/rpc/mining.cpp`.
- These checks run before template assembly. Proposal mode skips them.
- After assembly, any remaining mandatory template rule the client omitted
  is Core `-8`: `Support for 'NAME' rule requires explicit client support`.

### `API-11`: `submitblock` decode

- **Owner**: `decode_submitted_block` in `crates/rpc/src/handlers/mining.rs`.
  Admission stays on `MiningControl::submit_block`.
- Invalid hex or a payload that is not a complete block is Core `-22`
  (`Block decode failed`), matching Core `DecodeHexBlk`. Extra bytes after a
  complete block are ignored.
- A second dummy argument is accepted and ignored (BIP22). A third argument
  is JSON-RPC `-32602`.

### `API-12`: GBT proposal request parsing

- **Owner**: `parse_block_template_request` in
  `crates/rpc/src/handlers/mining.rs`.
- Unknown or non-string `mode` is Core `-8` (`Invalid mode`).
- Proposal mode does not require the client to list the `proposal`
  capability. Missing `data` is Core `-3`
  (`Missing data String key for proposal`). Decode uses
  `decode_submitted_block` (`API-11`): `-22` `Block decode failed`, leftover
  bytes ignored.

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
- `API-07`:
  - `crates/rpc/src/handlers/mining.rs` tests `getblocktemplate_forwards_longpollid`,
    `getblocktemplate_emits_submitold_and_omits_it_when_unset`,
    `getblocktemplate_requires_signet_rule_on_signet`
  - `crates/node/src/mining.rs` test `signet_template_carries_challenge_and_mandatory_rule`
  - `crates/node/tests/mining.rs` tests `template_does_not_echo_client_capabilities`,
    `signet_template_includes_challenge_and_signet_rule`
- `API-08`:
  - `crates/rpc/src/handlers/mining.rs` tests `getblocktemplate_rejects_mainnet_without_peers`,
    `getblocktemplate_rejects_mainnet_during_ibd`,
    `getblocktemplate_proposal_skips_mainnet_connection_gates`
- `API-09`:
  - `crates/rpc/src/handlers/mining.rs` tests `submitheader_rejects_undecodable_headers`,
    `submitheader_returns_null_and_forwards_decoded_header`,
    `submitheader_maps_rejected_to_verify_error`
  - `crates/node/tests/mining.rs` tests `submit_header_admits_a_mined_child_and_is_idempotent`,
    `submit_header_requires_the_previous_header`,
    `submit_header_rejects_bad_diffbits`,
    `submit_header_rejects_time_too_new`
  - `crates/node/src/mining.rs` tests `pow_failure_is_high_hash`,
    `nbits_mismatch_is_bad_diffbits`
- `API-10`:
  - `crates/rpc/src/handlers/mining.rs` tests `getblocktemplate_rejects_missing_segwit_rule`,
    `getblocktemplate_requires_signet_rule_on_signet`,
    `getblocktemplate_rejects_template_mandatory_rule_without_client_support`,
    `getblocktemplate_proposal_skips_client_rule_negotiation`
- `API-11`:
  - `crates/rpc/src/handlers/mining.rs` tests `submitblock_requires_mining_control_and_rejects_garbage_encoding`,
    `submitblock_ignores_bip22_dummy_and_trailing_bytes`
- `API-12`:
  - `crates/rpc/src/handlers/mining.rs` tests `getblocktemplate_rejects_invalid_mode`,
    `getblocktemplate_proposal_decode_matches_core`,
    `getblocktemplate_proposal_skips_client_rule_negotiation`
