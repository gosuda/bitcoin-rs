# External API contract

`API-01`–`API-04` place owners under the
[contracts precedence rule](README.md). `API-05` is the solo-mining generate
path. `API-06` is `getnetworkhashps` snapshot consistency. `API-07` is the
recorded Core reference used by the RPC fixture replay gate. `API-08` is
bounded public exposure. `API-09` is the Esplora dialects. `API-10` is
broadcast and preview through the admission gateway. `API-11` is the
BIP22/BIP23 `getblocktemplate` extras the pinned corepc type does not model.
`API-12` is mainnet template operational gates. `API-13` is `submitheader`.
`API-14` is GBT client-rule negotiation. `API-15` is `submitblock` decode.
`API-16` is GBT proposal request parsing. `API-17` is `submitblock` uncommitted
witness fill. `API-18` is Core v31 `submitblock` / GBT proposal duplicate
vocabulary. `API-19` is BIP22 reject-reason mapping. `API-20` is GBT
`vbrequired` always 0. `API-21` is Core `CheckWitnessMalleation`
reject reasons. `API-22` is GBT `coinbaseaux.flags`. `API-23` is
`prioritisetransaction` dummy/`fee_delta` arity. `API-24` is
`prioritisetransaction` dust-output refusal.

## Clauses

### `API-01`: Single manifest owner


- `MANIFEST` in `crates/rpc/src/manifest.rs` is the single source of truth
  for RPC, REST, and ZMQ external interfaces. A JSON-RPC method answers
  only when a non-`Unimplemented` row carries its name. No second route
  inventory exists.
- Each `Entry` row carries `name`, `kind` (`Rpc`, `Rest`, `Zmq`),
  `status`, `feature`, `core_version`, `notes`, and `since`, extended
  with required capabilities, error behavior, consistency class, resource
  budget, and evidence scenario. The `Status` vocabulary is unchanged:
  `Implemented`, `Deviation`, `Extension`, `Unimplemented`.
- Compatibility class, runtime readiness, and observed proof stay
  separate row facts. An unverified implementation never reads as
  verified parity.
- Unsupported Core surfaces stay declared `Unimplemented` and answer
  `RpcError::MethodNotFound` (code `-32601`). No wallet-only RPC is a
  disguised successful no-op.
- [docs/rpc-reference.md](../rpc-reference.md) is generated from the
  manifest and is never edited by hand.
  `crates/rpc/tests/manifest_coverage.rs` enforces set equality between
  the manifest and the live registry in both directions and regenerates
  the reference. Regenerate with:
  `REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage -- --ignored regenerate_reference`

### `API-02`: JSON-RPC mechanics and the wallet-free surface


- Parameter type and coercion rules, named and positional forms, the
  declared JSON-RPC 1 and 2 envelopes, batches, notifications,
  authentication, and error ordering follow the pinned Core 31.1
  contract.
- Failures map through `RpcError` (`crates/rpc/src/error.rs`): standard
  JSON-RPC codes (`-32700`, `-32600`..=`-32603`) and Core codes `-3`
  (invalid type), `-5` (not found), `-8` (invalid parameter), `-9`
  (not connected), `-10` (initial download), `-22` (deserialization),
  and `-25` plus `-26` (submission).
- Amounts are integer satoshis internally. Adapters render the exact
  external BTC or sat-per-vB units and precision.
- The node ships no wallet and holds no private key material. Methods
  that would reveal, import, create, or use private keys return
  `RpcError::MethodNotFound`. The key-free helpers `getdescriptorinfo`,
  `deriveaddresses`, `scantxoutset`, `combinepsbt`, and `finalizepsbt`
  remain supported. `scantxoutset` is a bounded and cancellable domain
  query, not wallet access to a live mutable map.

### `API-03`: REST dialect


- REST keeps its own HTTP semantics in `crates/rpc/src/rest.rs`: status
  codes, content types, empty bodies, and not-found behavior. No generic
  everything-is-JSON-RPC error handler spans the dialects.
- Formats are `json` (`application/json`), `hex` (`text/plain`), and
  `bin` (`application/octet-stream`). A disabled gateway and an unknown
  path return 404. Malformed parameters return 400. A well-formed but
  unknown block hash returns an empty 200, matching the pinned Core
  behavior.

### `API-04`: ZMQ notification contract


- `crates/rpc/src/zmq.rs` owns the declared Core topics
  `hashblock`, `hashtx`, `rawblock`, `rawtx`, and `sequence`, with Core
  byte order, sequence counters, and connect, disconnect, and mempool
  ordering.
- The `sequence` body frame is reversed txid (32 bytes), label byte (1),
  and little-endian sequence (8): 41 bytes total. `BlockInclusion` emits
  no `R` frame; every other removal reason does. One event per change, in
  commit order (`mempool-mutations.md` `MPL-03`).
- Delivery is bounded and optional. Queue overflow records a sticky gap
  and a reconcile signal instead of growing memory. High-water marks stay
  per endpoint (`DEFAULT_ZMQ_HWM = 1_000`). Canonical estimator and relay
  accounting is never dropped (`MPL-04`).

### `API-05`: Solo-mining generate path


- **Owner**: `MiningControl::generate` in `crates/mining/src/control.rs`,
  implemented by `MiningCoordinator::generate_blocks` in
  `crates/node/src/mining.rs`.
- The operation assembles a fresh candidate (no GBT cache), solves it, then
  either submits through the chainstate owner or dry-validates through
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
- The hash-rate window is Core's parent walk: `lookup` parent pointers from
  the resolved start node, min/max header time, `chainwork` delta. It does not
  re-resolve each height through `node_at_height_from`.
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

### `API-07`: RPC fixture reference provenance


- **Owner**: the corpus loader in `crates/rpc/tests/support/fixture.rs` owns
  `PINNED_CORE_VERSION`, `PINNED_CORE_SHA256`, and their validation. Every
  fixture records the version and exact binary digest used for its capture;
  missing, empty, or mismatched values fail loading before replay starts.
- These pins describe the released Core node used for the recorded RPC
  responses. They are separate from the `bitcoinkernel` oracle and from the
  broader API family declared by `MANIFEST` (`API-01`). Changing either of
  those references cannot relabel existing captures.
- `core_parity` replays recorded responses against bitcoin-rs. It does not
  execute or hash a local `bitcoind`, and the fixture metadata does not attest
  a source commit or build configuration. Verifying process binaries and
  recording those missing identities remain work under #625 and #626.
- The loader requires each fixture's version and digest to match the pins,
  so a reference refresh must update the constants and affected fixtures
  together. It only checks that `provenance.evidence` is non-empty; it does
  not retrieve or authenticate the referenced evidence. Reviewing evidence
  from the selected Core build is a maintainer responsibility outside this
  automated gate.

### `API-08`: Bounded public exposure


- Administrative RPC stays private and authenticated by default. Public
  read and broadcast exposure, allowed hosts and origins, and rate and
  concurrency limits are independently configured.
- Request bodies, batch size, response assembly, scan rows, in-flight
  work, and long-poll clients are bounded. A public explorer read cannot
  consume the CPU or memory quota needed to validate new blocks.

### `API-09`: Esplora dialects


- `/api` exposes the public Esplora (electrs) contract. `/esplora` is the
  versioned mempool-backend superset of that tree. Both project the same
  node and index state. Neither is a separate node mode or a second
  blockchain database, and no electrs proxy exists.
- `/api` is a closed namespace: a request inside it never falls through
  to JSON-RPC, and unprefixed electrs paths 404 so JSON-RPC keeps `/`.
  `/api/v1` belongs to the external mempool application's own API, not to
  this node.
- Beyond the public routes, the backend dialect requires `GET /internal/mempool/txs`,
  `GET /internal/block/{hash}/txs`, `POST /internal/txs`,
  `POST /internal/mempool/txs`, the batched outspends
  `POST /internal/txs/outspends/by-txid` and
  `POST /internal/txs/outspends/by-outpoint`, and address summaries.
  Only declared backend-dialect routes exist; each backend route is marked
  as such.
- History reads use bounded pages and cursors that preserve public
    Esplora cursor semantics. Cursor values
   are the exact lowercase `txid` display text: malformed, noncanonical
   (including uppercase or prefixed), unknown, and missing cursors restart from
   the beginning; a valid known cursor strictly excludes that transaction and
   earlier entries.
  A richer internal revision token stays
  internal or is a documented extension. Lag, reorg, or a disabled
  capability returns the declared unavailable response, never an empty
  successful history.

### `API-10`: Broadcast and preview through the admission gateway


- `sendrawtransaction`, `testmempoolaccept`, Esplora `POST /tx`, package
  submissions, and P2P ingress all reach the single `MempoolGateway`
  (`mempool-policy.md` `POL-02`). Each call carries an explicit
  `AdmissionOrigin` and its own request fee limits.
- Esplora is a distinct origin with its own request fee limits, not an
  alias for the RPC origin. Peer ingress does not inherit RPC limits.
- Preview runs the identical pipeline and mutates nothing: no membership,
  estimator, relay state, admission sequence, or victims (`POL-06`).
  `testmempoolaccept` returns preview rows in the frozen Core 31.1 shape
  with frozen reject-reason strings.
- Broadcast failures map to the Esplora error dialect: a rejected
  transaction is a 400 with the reject reason, not a retryable 503.

### `API-11`: BIP22/BIP23 template extras


- **Owner**: `MiningCoordinator::template_from_candidate` in
  `crates/node/src/mining.rs`; JSON projection in
  `crates/rpc/src/handlers/mining.rs` `render_block_template`.
- Capabilities are the producer’s implemented set (`proposal`, `longpoll`).
  Client-advertised names are not echoed.
- `submitold` is present after a long-poll wait and omitted otherwise. `workid`
  is not emitted.
- On signet, the template carries `signet` in `rules` (mandatory) and
  `signet_challenge`. Other networks omit `signet_challenge`.
  - Malformed `longpollid` values, including invalid UTF-8 split boundaries, are rejected without panicking.

### `API-12`: Mainnet template operational gates


- **Owner**: `ensure_template_ready` in `crates/rpc/src/handlers/mining.rs`.
- Template mode on mainnet requires at least one live peer (`PeerTable`) and
  that the node has left IBD (`Context::is_initial_block_download`). Failures
  are Core `-9` (`bitcoin-rs is not connected!`) and `-10`
  (`bitcoin-rs is in initial sync and waiting for blocks...`).
- Proposal mode does not apply these gates. Networks other than mainnet skip
  them, matching Core `IsTestChain()`.

### `API-13`: `submitheader`


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

### `API-14`: GBT client-rule negotiation


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

### `API-15`: `submitblock` decode


- **Owner**: `decode_submitted_block` in `crates/rpc/src/handlers/mining.rs`.
  Admission stays on `MiningControl::submit_block`.
- Invalid hex or a payload that is not a complete block is Core `-22`
  (`Block decode failed`), matching Core `DecodeHexBlk`. Extra bytes after a
  complete block are ignored.
- A second dummy argument is accepted and ignored (BIP22). A third argument
  is JSON-RPC `-32602`.

### `API-16`: GBT proposal request parsing


- **Owner**: `parse_block_template_request` in
  `crates/rpc/src/handlers/mining.rs`.
- Unknown or non-string `mode` is Core `-8` (`Invalid mode`).
- Proposal mode does not require the client to list the `proposal`
  capability. Missing `data` is Core `-3`
  (`Missing data String key for proposal`) with no `invalid type:` prefix.
  Decode uses
  `decode_submitted_block` (`API-15`): `-22` `Block decode failed`, leftover
  bytes ignored.

### `API-17`: `submitblock` uncommitted witness nonce


- **Owner**: `update_uncommitted_block_structures` in
  `crates/mining/src/coinbase.rs`, called from
  `MiningCoordinator::submit_block` in `crates/node/src/mining.rs`.
- When the previous header is known, SegWit is active for the submitted
  height, the coinbase already has a BIP141 commitment output, and the
  coinbase witness is empty, `submitblock` inserts the 32-byte reserved
  nonce. This matches Core `UpdateUncommittedBlockStructures`.
- An existing coinbase witness is left unchanged. Proposal mode does not
  apply this fill.

### `API-18`: `submitblock` and proposal duplicate vocabulary


- **Owner**: `MiningCoordinator::known_block_result` in
  `crates/node/src/mining.rs`.
- GBT proposal looks the block hash up first, matching Core
  `LookupBlockIndex`: a node on the applied chain is `duplicate`,
  `Invalid` is `duplicate-invalid`, and any other tree entry (including a
  header-only tip) is `duplicate-inconclusive`.
- `submitblock` matches Core v31 `ProcessNewBlock`: only an already
  accepted block is `duplicate`. A header admitted by `submitheader` still
  receives the body.

### `API-19`: BIP22 reject reasons


- **Owner**: `bip22_reject_reason` in `crates/node/src/mining.rs`.
- Proposal and `submitblock` project apply/consensus failures as Core
  `GetRejectReason` strings (`bad-cb-missing`, `bad-txnmrklroot`,
  `bad-cb-amount`, `high-hash`, `time-too-old`, …). Operational apply
  refusals (`Shutdown`, journal backpressure) stay `inconclusive`.
- Consensus crate Display remains log text. This mapping is the BIP22
  wire owner.

### `API-20`: GBT `vbrequired` is always 0


- **Owner**: `MiningCoordinator::version_bits_for` in
  `crates/node/src/mining.rs`.
- Core v31 `getblocktemplate` hardcodes `vbrequired` to 0. Signalling
  deployments still appear in `vbavailable`; locked-in bits are not OR'd
  into `vbrequired`.

### `API-21`: BIP141 witness malleation reasons


- **Owner**: `check_witness_malleation` in
  `crates/consensus/src/verify_block.rs`.
- Core `CheckWitnessMalleation` distinguishes three BIP22 strings:
  - commitment present, coinbase witness not a single 32-byte element →
    `bad-witness-nonce-size`
  - commitment present, reserved nonce well-formed, hash mismatch →
    `bad-witness-merkle-match`
  - witness data without a commitment, or before SegWit →
    `unexpected-witness`
- Proposal does not fill an omitted reserved nonce (`API-17` is
  `submitblock`-only), so an empty coinbase witness with a commitment is
  miner-facing `bad-witness-nonce-size`.
- `bip22_reject_reason` maps the consensus variants; consensus Display
  remains log text.

### `API-22`: GBT `coinbaseaux.flags` is empty hex


- **Owner**: `render_block_template` in `crates/rpc/src/handlers/mining.rs`.
- Core v31 emits `coinbaseaux: { "flags": HexStr(COINBASE_FLAGS) }`. The
  flags bytes are empty, so the hex string is `""`. An empty object is not
  the Core shape.

### `API-23`: `prioritisetransaction` dummy and `fee_delta`


- **Owner**: `prioritisetransaction` in `crates/rpc/src/handlers/mining.rs`.
- Core reads `fee_delta` from params[2] (`getInt<int64_t>`). The deprecated
  dummy (params[1]) must be omitted, null, or numeric zero; any other value
  is `-8` `Priority is no longer supported, dummy argument to
  prioritisetransaction must be 0.`
- Two-argument calls do not treat params[1] as `fee_delta`.

### `API-24`: `prioritisetransaction` refuses pooled dust


- **Owner**: `prioritisetransaction` in `crates/rpc/src/handlers/mining.rs`.
- Core v31 rejects a mempool transaction with dust outputs when
  `require_standard` is set: `-8` `Priority is not supported for
  transactions with dust outputs.`
- `require_standard` follows Core's `-acceptnonstdtxn` default: enforced
  everywhere except regtest. Absent txids (fee-delta overlay only) are
  not checked. Dust classification uses the pool's dust-relay fee via
  `tx_has_dust_outputs`.

The wallet-facing subset of this surface — tip, fees, address/script
queries, and broadcast over Esplora, plus the key-free node RPCs — is
owned by [wallet-facing.md](wallet-facing.md).

## Live gaps

- **Full Core differential suite**: Versioned Core response structs, golden fixtures, and differential test lanes across all RPC methods are tracked under #78 (open).
- **Typed embedding surface**: Direct in-process application API as an alternative to localhost JSON-RPC daemon boundary is tracked under #145 (open).

## Proven by


## Vocabulary


