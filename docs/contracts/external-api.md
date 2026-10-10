# External API contract

`API-01`–`API-32` govern RPC, REST, Esplora and ZMQ under the
[contracts precedence rule](README.md). The clauses below own each behavior;
[Proven by](#proven-by) separates existing tests from planned comparisons.

## Clauses

### `API-01`: Single manifest owner


- `REGISTRY` in `crates/rpc/src/registry.rs` is the single source of truth
  for RPC, REST, and ZMQ external interfaces: each row binds one dispatch
  arm to one compatibility claim. `MANIFEST` in
  `crates/rpc/src/manifest.rs` projects those rows. A JSON-RPC method
  answers only when a non-`Unimplemented` row carries its name. No second
  route inventory exists.
- Each `Entry` row carries `name`, `kind` (`Rpc`, `Rest`, `Zmq`),
  `status`, `feature`, `core_version`, `notes`, and `since`, extended
  with required capabilities, error behavior, consistency class, resource
  budget, and evidence scenario. The `Status` vocabulary is `Supported`,
  `Deviation`, `Implemented (unverified)`, `Extension`, `Disabled`,
  `Unimplemented`. `[reference].differential_harness` in
  [core-compat.toml](../../crates/rpc/core-compat.toml) gates `Supported`: no row
  may claim it while that flag is false. Compatibility class, runtime
  readiness, and observed proof stay separate row facts; an unverified
  implementation never reads as verified parity.
- Unsupported Core surfaces stay declared `Unimplemented` and answer
  `RpcError::MethodNotFound` (code `-32601`). No wallet-only RPC is a
  disguised successful no-op.
- [docs/rpc-reference.md](../rpc-reference.md) is generated from the
  registry and is never edited by hand.
  `crates/rpc/tests/manifest_coverage.rs` enforces set equality between
  the registry and the live dispatch table in both directions and
  regenerates the reference. Regenerate with:
  `REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage -- --ignored regenerate_reference`

### `API-02`: JSON-RPC mechanics and the wallet-free surface


- Parameter type and coercion rules, named and positional forms, the
  declared JSON-RPC 1 and 2 envelopes, batches, notifications,
  authentication, and error ordering follow the pinned Core 31.1
  contract.
- Failures map through `RpcError` (`crates/rpc/src/error.rs`): standard
  JSON-RPC codes (`-32700`, `-32600`..=`-32603`) and Core codes `-1`
  (miscellaneous runtime failure), `-3` (invalid type), `-5` (not found), `-8` (invalid parameter), `-9`
  (not connected), `-10` (initial download), `-22` (deserialization),
  and `-25` plus `-26` (submission).
- Amounts are integer satoshis internally. Adapters render the exact
  external BTC or sat-per-vB units and precision. Shared transaction JSON
  interprets raw version bits as Core's unsigned 32-bit value and raw output
  amounts as signed 64-bit values; native transaction representations and
  consensus checks are unchanged.
- The node ships no wallet and holds no private key material. Methods
  that would reveal, import, create, or use private keys return
  `RpcError::MethodNotFound`. The key-free helpers `getdescriptorinfo`,
  `deriveaddresses`, `decodescript`, `scantxoutset`, `combinepsbt`, and `finalizepsbt`
  remain supported. `scantxoutset` is a bounded and cancellable domain
  query, not wallet access to a live mutable map.

- Core script JSON has one projection owner in `tx_render.rs`: decimal short
  pushes, malformed-instruction markers, checksummed inferred descriptors,
  and optional address/hex fields. Transaction inputs alone decode defined
  sighash suffixes. Esplora retains its separate opcode/push spelling.
- `decodescript` uses the native instruction parser and script validity
  predicates. Wrapper eligibility follows Core 31.1, and P2WSH inference
  receives only its redeem script, with no key provider. Parsed Miniscript
  properties enforce Core's sanity checks, including sane unsatisfiable
  scripts; no second script parser or signing state is introduced.
- `decodescript` accepts positional and named `hexstring` forms. Its
  declared differences are compact usage text for missing/extra arguments,
  a direct-call hex-input limit equal to the 16 MiB HTTP body budget, and
  address-descriptor fallback when a complex Miniscript contains an
  invalid-curve public key rejected by the Miniscript parser. Core can
  infer `wsh(...)` from that syntactically encoded key; the fallback retains
  the same script, addresses and wrappers. Bare P2PK/multisig inference
  keeps Core's syntactic key handling.
  This is an input/work limit, not a response-size limit: disassembly and
  descriptors can be larger than their input. No response-memory or
  performance claim follows from the input limit. The pinned process matrix
  in `overhaul_process_harness::script_decode_cases` covers script classes,
  invalid encodings, wrappers, descriptor checksums, parameters, network
  addresses, and shared RPC/REST/UTXO projections.

- PSBT reads and output serialization share `crates/rpc/src/psbt.rs`, using
  the library codec with complete-consumption and non-witness UTXO hash/index
  postconditions. Core's signed -1 witness-UTXO sentinel becomes absent;
  negative amounts inside non-witness transactions are retained. Encoding
  strips witness bytes from a non-witness UTXO transaction and gates known
  nonfinal input metadata only when final scriptSig/witness is nonempty,
  matching Core serialization. Empty redeem/witness scripts in both input and
  output maps are omitted on encoding. An encoding copy preserves parsed/caller
  metadata for decode, analyze and join. Already
  decoded CompactSize types/subtypes and BIP373 fields receive Core checks.
- PSBT admission limits encoded inputs/outputs to 16 MiB, input plus output
  maps to 10,000, and retained map entries to 100,000. Creators can check
  counts before map allocation. Serialized bytes are checked before library
  input decoding; structural checks occur after that decode and do not
  claim to prevent its intermediate allocations. Combine checks aggregate
  source bytes before each decode and counts before each merge. The output
  writer bounds accumulated bytes; the library still materializes individual
  maps, bounded for combine by the aggregate admitted source bytes. Encoded
  output is re-read through the same library before returning, including its
  4,000,000-byte global-map limit; pure creators therefore cannot emit a PSBT
  the shared decoder cannot read.
- `combinepsbt` and `finalizepsbt` retain their existing malformed-input
  `-32602` boundary instead of Core's `-22`. Their stricter library field
  validation/finalization and the admission limits remain declared deviations.
  The typed library canonically orders TapTree sibling branches rather than
  retaining their original byte/JSON order. The exact `core-valid-18` fixture
  and independent Core descriptor derivation verify the same commitment;
  no raw-tree sidecar is kept. An admission-only check of library-validated framing rejects an explicit
  65-byte Taproot DEFAULT suffix, which the typed reader would otherwise drop.
  Core retains those bytes; dropping them could change signature validity.
  Unknown sighash values are also rejected instead of retained. Permanent
  `probe-taproot-65-explicit-default` and `probe-taproot-65-unknown` vectors record
  those exact differences. No wallet, signing authority, or parallel PSBT
  parser is introduced.

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
  implemented by `MiningCoordinator::generate` in
  `crates/node/src/mining.rs`, which assembles each block through
  `MiningService::assemble_fresh` in `crates/mining/src/coordinator.rs`.
- The operation assembles a fresh candidate (no GBT cache). `generateblock`
  validates the unsolved block first (`API-30`), then both generate paths
  solve and either submit through the chainstate owner or dry-validate
  through `Chainstate::validate_block` (`ARCH-07`). Persistence and tip
  advancement are conditional on `submit`; validation is not.
- Each submitted block is a separate commit. An error after *N* successful
  submissions leaves those *N* blocks durable. Callers own retry after reading
  the applied tip. `nblocks` is not capped; the result vector grows one block
  at a time.
- `generatetoaddress` accepts only a network-valid address, uses mempool
  package selection, collects fees, and always submits.
- `generateblock` accepts an address or descriptor (`require_checksum = false`;
  a supplied checksum is verified). Ranged and multipath descriptors are
  refused (`API-31`). The transactions array is required (an explicit `[]` is
  coinbase-only).
  Listed order is kept, those fees are not added to the coinbase, 64-character
  hex is a mempool txid, and decoded raw transactions are included without
  mempool admission. Raw transaction sigop costs use copied applied-chain
  prevouts and outputs of earlier listed transactions, with the candidate's
  witness activation. The node captures those inputs under the existing chain
  read fence and computes costs after releasing locks. Unselected or later
  mempool transactions do not supply previous outputs. Missing inputs still
  pass to authoritative block validation. Extra positional arguments are
  rejected. Output parse errors are `API-29`. Consensus failures before the
  nonce search are `API-30`.

### `API-06`: `getnetworkhashps` snapshot and invalid-height behavior


- **Owner**: `network_hash_ps` in `crates/mining/src/network_hashps.rs`.
  Node `MiningCoordinator::network_hash_ps` only supplies the locked block tree
  and one applied-tip snapshot.
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
  the `core_version` and `core_binary_sha256` provenance pins and their
  validation. Every fixture records the version and exact binary digest used
  for its capture; missing, empty, or mismatched values fail loading before
  replay starts.
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


- `sendrawtransaction`, `testmempoolaccept`, Esplora `POST /tx`, and P2P
  ingress reach the single `MempoolGateway` (`mempool-policy.md` `POL-02`).
  Each committing producer carries an explicit `AdmissionOrigin` and its
  own request fee limits. Aggregate package submission remains unsupported
  (`POL-05`); its future producer must use this same admission owner.
- Esplora `POST /tx` is implemented on both `/api` and `/esplora` with
  `AdmissionOrigin::Esplora` and an explicit, fixed 10,000,000 sat/kvB
  request ceiling. Its hex body provides no fee override. RPC keeps its
  own default and `maxfeerate` override; peer ingress has no request cap.
  The shared gateway owns fee verification and authoritative mutation.
- Preview runs the identical pipeline and mutates nothing: no membership,
  estimator, relay state, admission sequence, or victims (`POL-06`).
  `testmempoolaccept` returns preview rows in the frozen Core 31.1 shape
  with frozen reject-reason strings.
- Broadcast failures map to the Esplora error dialect: a rejected
  transaction is a 400 with the reject reason, not a retryable 503.

### `API-11`: BIP22/BIP23 template extras


- **Owner**: `template_from_candidate` in `crates/mining/src/coordinator.rs`,
  driven by `MiningService::get_block_template`; JSON projection in
  `crates/rpc/src/handlers/mining.rs` `render_block_template`.
- Capabilities are the producer’s implemented set (`proposal`, `longpoll`).
  Client-advertised names are not echoed.
- `submitold` and `workid` are BIP23 extras the pinned template contract
  does not model; neither is emitted.
- On signet, the template carries `signet` in `rules` (mandatory) and
  `signet_challenge`. Other networks omit `signet_challenge`.
  - Malformed `longpollid` values, including invalid UTF-8 split boundaries, are rejected without panicking.

### `API-12`: Mainnet template operational gates


- **Owner**: `ensure_template_ready` in `crates/rpc/src/handlers/mining.rs`.
- Template mode on mainnet requires at least one live peer (`PeerTable`) and
  that the node has left IBD
  (`!ctx.chain.ibd.is_active(now, ctx.chain.chain_network)`, the chain-crate
  latch in `crates/chain/src/ibd.rs` negated by the gate).
  Failures are Core `-9` (`bitcoin-rs is not connected!`) and `-10`
  (`bitcoin-rs is in initial sync and waiting for blocks...`).
- Proposal mode does not apply these gates. Networks other than mainnet skip
  them, matching Core `IsTestChain()`.

### `API-13`: `submitheader`


- **Owner**: `MiningCoordinator::submit_header` in `crates/node/src/mining.rs`.
  RPC decodes the hex and projects the result; it does not admit headers.
  The reject-reason projection is `header_reject_reason` in
  `crates/mining/src/bip22.rs`; authoritative admission runs through
  `Chainstate::admit_headers`.
- Decode failures (invalid hex, fewer than 80 bytes) are Core `-22`
  (`Block header decode failed`). Extra bytes after an 80-byte header are
  ignored, matching Core `DecodeHexBlockHeader`.
- For an unknown header, the previous header must already be in the block tree,
  except that an empty tree admits the network's genesis header as its root.
  Otherwise the RPC returns `-25` (`Must submit previous header (HASH) first`)
  before proof-of-work validation, including when the target is invalid.
- Admission uses `accept_headers`, the same consensus gate as inbound P2P
  headers, so `submitheader` cannot admit a header the network would reject.
  Known-valid duplicates (including genesis) succeed. Known-invalid
  duplicates return `-25` (`duplicate-invalid`); a header that extends one
  this node has marked invalid returns `-25` (`bad-prevblk`). Other invalid
  headers return `-25` with Core reject reasons (`high-hash`, `bad-diffbits`,
  `time-too-old`, `time-too-new`, `bad-version(0x%08x)`,
  `time-timewarp-attack`).
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
  `LookupBlockIndex`: a node whose body is connected (scripts-valid) is
  `duplicate`, `Invalid` is `duplicate-invalid`, and any other tree entry
  (including a header-only tip) is `duplicate-inconclusive`.
- `submitblock` matches Core v31 `ProcessNewBlock`: a previously connected
  body (scripts-valid), including after a later reorg, is `duplicate`. A
  header admitted by `submitheader` still receives the body.
- Duplicate classification holds the chain-transition lock through apply, so
  concurrent submissions of one body cannot race into a previous-tip refusal.

### `API-19`: BIP22 reject reasons


- **Owner**: `bip22_reject_reason` in `crates/node/src/mining.rs`
  for the `ApplyError` arms, delegating to `consensus_reject_reason` and
  `chain_reject_reason` in `crates/mining/src/bip22.rs`.
- Proposal and `submitblock` project apply/consensus failures as Core
  `GetRejectReason` strings (`bad-cb-missing`, `bad-txnmrklroot`,
  `bad-cb-amount`, `high-hash`, `time-too-old`, …). Operational apply
  refusals (`Shutdown`, journal backpressure) stay `inconclusive`.
- Storage, UTXO, durable-head, and internal verifier failures propagate as
  `MiningControlError::Failed`, never as a BIP22 block rejection. The same
  distinction applies to `generateblock` prevalidation.
- Consensus crate Display remains log text. This mapping is the BIP22
  wire owner.

### `API-20`: GBT `vbrequired` is always 0


- **Owner**: `template_from_candidate` in
  `crates/mining/src/coordinator.rs` (driven by
  `MiningService::get_block_template`); signalling deployments are read from
  the applied tree through the node-implemented `ChainContextSource`.
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


### `API-25`: `getmininginfo` omits unset optional fields

- **Owner**: `render_mining_info` in `crates/rpc/src/handlers/mining.rs`.
- Core pushes `currentblockweight`, `currentblocktx`, and `signet_challenge`
  only when set. Unset optionals are omitted, not JSON `null`.
- Projection uses `typed_to_sonic_omitting_nulls`.


### `API-26`: `estimatesmartfee` Core `conf_target` and `estimate_mode`

- **Owner**: `estimatesmartfee` in `crates/rpc/src/handlers/util.rs`.
- `conf_target` must be in `1..=1008` (Core `MAX_CONFIRM_TARGET`). Otherwise
  `-8` `Invalid conf_target, must be between 1 and 1008`.
- `estimate_mode` is optional, case-insensitive `UNSET` / `ECONOMICAL` /
  `CONSERVATIVE` (Core `FeeModeFromString`). Unknown strings are `-8`
  `Invalid estimate_mode parameter, must be UNSET, ECONOMICAL or
  CONSERVATIVE`. A non-string is `-3`. Accepted modes are parsed only;
  this node's estimator does not differentiate ECONOMICAL from CONSERVATIVE.
- The estimator has a 25-block horizon (`MAX_CONF_TARGET = 25`), so a
  `conf_target` above 25 is answered with the 25-block fee rate.
- Insufficient data for the requested target omits `fee_rate` and returns an
  `errors` array containing `Insufficient data or no feerate found`.
- Trailing parameters are refused.


### `API-27`: `generateblock` txid and raw-tx parse errors

- **Owner**: `parse_generateblock_transactions` in
  `crates/rpc/src/handlers/mining.rs`.
- 64-character hex is Core `Txid::FromHex`. A txid missing from the
  mempool is `-5` `Transaction {str} not in mempool.` using the caller's
  string.
- Anything else is Core `DecodeHexTx`. Invalid hex or a payload that is
  not a complete transaction is `-22`
  `Transaction decode failed for {str}. Make sure the tx has at least one
  input.`


### `API-28`: `getprioritisedtransactions` `modified_fee` is satoshis

- **Owner**: `getprioritisedtransactions` in
  `crates/rpc/src/handlers/mining.rs`.
- Core mining RPCs use satoshi amounts, not BTC. `fee_delta` is already
  an integer satoshi overlay. `modified_fee` (actual fee plus delta,
  present only when `in_mempool`) is the same unit: a JSON number in
  satoshis, matching Core `CAmount`.


### `API-29`: generate invalid-output text

- **Owner**: `generateblock_payout_script` in
  `crates/rpc/src/handlers/util.rs`; `generatetoaddress` in
  `crates/rpc/src/handlers/mining.rs`.
- `generatetoaddress` refuses a non-address with `-5`
  `Error: Invalid address`.
- `generateblock` tries a descriptor first (`require_checksum = false`).
  Ranged/multipath descriptors are `-8` (`API-31`). If Parse fails, the text is
  tried as an address; a miss is `-5`
  `Error: Invalid address or descriptor`, matching Core
  `src/rpc/mining.cpp`. A supplied checksum that fails Parse is refused
  through that fallback, not CheckChecksum's wording.


### `API-30`: `generateblock` `TestBlockValidity` before solve

- **Owner**: `MiningCoordinator::generate` in
  `crates/node/src/mining.rs`.
- Core v31 `generateblock` runs `TestBlockValidity` with
  `check_pow = false` and `check_merkle_root = false` before
  `GenerateBlock`. Failure is Core `-25`
  (`RpcError::TxVerifyError`) `TestBlockValidity failed: {reason}`,
  where `{reason}` is the BIP22 GetRejectReason string (`API-19`).
- This pre-check applies only to `GenerateSelection::Ordered`
  (`generateblock`). An ordered candidate refused by the mining sigop
  preflight also returns this `-25` envelope with `bad-blk-sigops`; it does
  not become an operational `Failed` result. `generatetoaddress` (`Mempool`)
  matches Core `generateBlocks` and does not run it.
- The check calls `apply::validate_block` directly.
  `ApplyIntent::Propose` already skips hash-meets-target. It does not
  go through GBT `propose` (`API-18` LookupBlockIndex vocabulary).
  Shutdown and journal backpressure stay `Unavailable`,
  not TestBlockValidity.


### `API-31`: `generateblock` multipath, ranged, and Expand errors

- **Owner**: `generateblock_payout_script` in
  `crates/rpc/src/handlers/util.rs`.
- Core `getScriptFromDescriptor` throws before the address fallback:
  - more than one parsed descriptor → `-8`
    `Multipath descriptor not accepted`
  - `IsRange()` → `-8`
    `Ranged descriptor not accepted. Maybe pass through deriveaddresses first?`
  - `Expand(0)` failure → `-5`
    `Cannot derive script without private keys`
- Multipath is checked first, matching Core `descs.size() > 1` before
  `IsRange()`. A descriptor that is both is the multipath error.

### `API-32`: `gettxspendingprevout` mempool snapshot

- **Owner**: `Mempool::outpoint_spender` owns the spending-index lookup and
  its typed consistency failure. The RPC adapter validates every input before
  taking one gateway read guard, captures spending transaction references for
  all outpoints under that guard, and serializes after releasing it.
- Results preserve query order, duplicates, and the caller's txid spelling.
  A row without a mempool spender contains only `txid` and `vout`; no
  confirmed-spend history is queried. Replacement and removal are visible
  through the existing mempool index, with no additional state.
- Positional and named `outputs` / `options`, flattened named options, and
  the `args` positional prefix accept Core 31.1's `mempool_only` and
  `return_spending_tx` options. The default is mempool-only; requested
  `spendingtx` uses full consensus serialization, including witness.
  With `mempool_only=false`, a missing mempool spender fails with Core's
  `-1` unavailable-txospenderindex error. An inconsistent spending index
  becomes an internal error, never an unspent result.
- Empty output lists, strict object keys, txid syntax, and signed 32-bit
  nonnegative vout validation follow the pinned reference. Missing or extra
  argument counts retain local JSON-RPC `-32602` shape errors instead of
  Core's `-1` help text; the registry declares this deviation.
- The HTTP request-body limit bounds externally supplied queries; this
  handler retains O(number of requested outputs) rows and transaction
  references. It never scans or clones the full mempool.

## Live gaps

- **Full Core differential suite**: Versioned Core response structs, golden fixtures, and differential test lanes across all RPC methods are tracked under #78 (open).
- **Typed embedding surface**: Direct in-process application API as an alternative to localhost JSON-RPC daemon boundary is tracked under #145 (open).

## Proven by

- `API-07`: `crates/rpc/tests/core_parity.rs` test
  `corpus_bounds_and_provenance_hold` and `support::fixture::tests`:
  - `copied_fixture_preserves_core_reference`
  - `corpus_rejects_missing_core_reference_fields`
  - `corpus_rejects_non_pinned_core_version`
  - `corpus_rejects_mismatched_or_empty_core_digest`
- `bin/bitcoin-rs/tests/overhaul_core_api.rs` (planned): every required
  manifest row driven statefully against the pinned reference, including
  auth negatives, batches, notifications, fee units, ZMQ sequence bytes
  and order, unsupported methods, unavailable-capability errors, and
  cancellation.
- `bin/bitcoin-rs/tests/overhaul_esplora.rs` (planned): pinned-schema
  equality per public and backend route, unavailable states for lag,
  reorg, and disabled capability, broadcast reaching the gateway with the
  Esplora origin, and reorg mid-query.
- Existing: `crates/rpc/tests/manifest_coverage.rs` tests
  `rpc_rows_and_the_live_registry_agree_both_ways`,
  `rest_rows_and_router_registrations_agree_both_ways`,
  `zmq_rows_are_valid_core_topics`,
  `every_unimplemented_rpc_row_answers_method_not_found`,
  `generated_reference_matches_checked_in`;
  `crates/rpc/tests/handler_smoke.rs`;
  `crates/rpc/src/esplora.rs` tests
  `esplora_lives_only_under_the_api_prefix`,
  `api_is_the_public_electrs_directory`,
  `esplora_is_the_mempool_backend_superset`.
- `API-05` and `API-06`, existing:
  `crates/rpc/src/handlers/mining.rs` tests
  `generatetoaddress_projects_solved_hashes`,
  `generatetoaddress_rejects_script_hex_and_descriptors`,
  `generateblock_projects_hash_object`,
  `generateblock_accepts_addr_descriptor`,
  `generateblock_without_submit_includes_hex`,
  `generateblock_requires_transactions_array`,
  `generateblock_keeps_raw_transactions`,
  `generateblock_rejects_trailing_parameters`,
  `generateblock_rejects_invalid_supplied_checksums`,
  `getnetworkhashps_projects_control_invalid_request_as_invalid_parameter`;
  `crates/node/tests/mining.rs` tests
  `generate_mines_coinbase_only_blocks_to_the_tip`,
  `generateblock_rejects_unknown_mempool_txid`,
  `generateblock_raw_tx_does_not_require_mempool_admission`,
  `generate_without_submit_does_not_advance_the_tip`,
  `network_hash_ps_rejects_core_invalid_windows`;
  `crates/mining/src/network_hashps/oracle_tests.rs` tests
  `network_hash_ps_rejects_a_height_the_tip_cannot_resolve`;
  `crates/mining/tests/template_shape.rs` tests
  `candidate_solves_an_unsolved_regtest_header`,
  `ordered_assembly_keeps_snapshot_order`.

- `API-10`:
  - `crates/rpc/src/esplora.rs` tests
    `broadcast_preserves_esplora_origin_and_idempotence`,
    `broadcast_rejections_are_400_without_mutation`,
    `broadcast_fee_ceiling_is_independent_of_rpc_overrides`, and
    `broadcast_fee_ceiling_accepts_equality_and_refuses_one_sat_above`.
  - `crates/rpc/src/esplora/http.rs` test
    `admission_consensus_and_retry_failures_preserve_the_http_dialect`.
  - `crates/p2p/src/tx_relay.rs` local relay and delayed-event tests include
    Esplora origins; mempool admission tests cover orphan wakeups and absence
    of peer lifecycle state for local missing-input refusals.
  - `bin/bitcoin-rs/tests/wallet_facing.rs` test
    `external_wallet_can_scan_estimate_and_broadcast` exercises both HTTP
    broadcast directories' maximum-fee and malformed-input refusals, followed
    by an accepted transaction whose returned id is checked with rust-bitcoin.

- `API-11`:
  - `crates/rpc/src/handlers/mining.rs` tests `getblocktemplate_forwards_longpollid`,
    `getblocktemplate_requires_signet_rule_on_signet`
  - `crates/mining/src/coordinator/candidate_template_tests.rs` tests
    `template_facts_follow_mutated_candidate_generation`,
    `signet_template_carries_challenge_and_mandatory_rule`
  - `crates/node/tests/mining.rs` tests `template_does_not_echo_client_capabilities`,
    `signet_template_includes_challenge_and_signet_rule`

- `API-12`:
  - `crates/rpc/src/handlers/mining.rs` tests `getblocktemplate_rejects_mainnet_without_peers`,
    `getblocktemplate_rejects_mainnet_during_ibd`,
    `getblocktemplate_proposal_skips_mainnet_connection_gates`
- `API-13`:
  - `crates/rpc/src/handlers/mining.rs` test
    `submitheader_maps_armed_control_failure`; `e2e/tests/mining.rs` tests
    `mining_rejections_carry_core_error_codes` (decode `-22`) and
    `template_assembly_header_then_block` (null success)
  - `crates/node/tests/mining.rs` tests `submit_header_admits_a_mined_child_and_is_idempotent`,
    `submit_header_accepts_genesis_before_and_after_bootstrap`,
    `submit_header_requires_the_previous_header`,
    `submit_header_rejects_bad_diffbits`,
    `submit_header_rejects_time_too_new`
  - `crates/mining/src/bip22/tests.rs` test
    `header_reject_reason_uses_chain_vocabulary`
    - Execution evidence: `cargo test -p bitcoin-rs-mining bip22` and
      `cargo test -p bitcoin-rs-rpc submitheader` (CI job `test`, commit `adc8e37`).
    - Core reference: Bitcoin Core v30.0 `src/rpc/mining.cpp` (`submitheader`)
      and `src/validation.cpp` header reject reasons (tag `v30.0`).

- `API-14`:
  - `crates/rpc/src/handlers/mining.rs` tests `getblocktemplate_requires_signet_rule_on_signet`,
    `getblocktemplate_rejects_template_mandatory_rule_without_client_support`,
    `getblocktemplate_rejects_missing_segwit_rule`,
    `getblocktemplate_proposal_skips_client_rule_negotiation`
  - `bin/bitcoin-rs/tests/overhaul_external_miner.rs` test
    `external_miner_assembles_template_and_submits_block` (external consumer
    negotiates `{"rules": ["segwit"]}` through the production handler)

- `API-15`:
  - `crates/rpc/src/handlers/mining.rs` tests `submitblock_requires_mining_control_and_rejects_garbage_encoding`,
    `submitblock_ignores_bip22_dummy_and_trailing_bytes`
  - `bin/bitcoin-rs/tests/overhaul_external_miner.rs` test
    `external_miner_assembles_template_and_submits_block` (external consumer
    submits the assembled block over production HTTP)
- `API-16`:
  - `crates/rpc/src/handlers/mining.rs` tests `getblocktemplate_rejects_invalid_mode`,
    `getblocktemplate_proposal_decode_matches_core`,
    `getblocktemplate_proposal_skips_client_rule_negotiation`
- `API-17`:
  - `crates/mining/src/coinbase.rs` tests `fills_reserved_nonce_when_commitment_present_and_witness_empty`,
    `leaves_an_existing_coinbase_witness_alone`,
    `skips_without_commitment_or_when_segwit_is_inactive`
  - `crates/node/tests/mining.rs` test `submit_block_fills_omitted_coinbase_witness`
- `API-18`:
  - `crates/node/tests/mining.rs` tests `submit_block_applies_a_header_already_in_the_tree`,
    `proposal_of_an_applied_block_is_duplicate`,
    `proposal_of_an_invalid_header_is_duplicate_invalid`,
    `proposal_of_a_header_only_block_is_duplicate_inconclusive`,
    `proposal_of_a_disconnected_scripts_valid_block_is_duplicate`,
    `submit_of_a_disconnected_scripts_valid_block_is_duplicate`,
    `applied_ancestor_with_unset_chain_tx_count_is_duplicate`,
    `duplicate_submit_returns_duplicate`
- `API-19`:
  - `crates/mining/src/bip22/tests.rs` tests
    `consensus_failures_use_core_bip22_reasons`, `header_failures_use_core_bip22_reasons`;
    `crates/node/tests/unit/mining/apply_error_tests.rs` test
    `apply_errors_delegate_consensus_and_chain_reasons`
  - `crates/node/tests/mining.rs` tests `proposal_without_coinbase_is_bad_cb_missing`,
    `proposal_merkle_mismatch_is_bad_txnmrklroot`,
    `proposal_rejects_excess_coinbase_without_side_effects`
- `API-20`:
  - `crates/node/tests/mining.rs` test `template_does_not_echo_client_capabilities`
- `API-21`:
  - `crates/consensus/src/verify_block.rs` tests
    `contextual_rules_reject_witness_before_segwit_activation`,
    `contextual_rules_enforce_bip141_commitment_after_segwit_activation`,
    `bip141_coinbase_witness_must_have_exactly_one_32_byte_element`,
    `bip141_witness_commitment_last_output_wins`
  - `crates/mining/src/bip22/tests.rs` test
    `consensus_failures_use_core_bip22_reasons`
  - `crates/node/tests/mining.rs` tests
    `proposal_commitment_without_witness_nonce_is_bad_witness_nonce_size`,
    `proposal_witness_without_commitment_is_unexpected_witness`,
    `proposal_wrong_witness_commitment_is_bad_witness_merkle_match`
- `API-22`:
  - `crates/rpc/src/handlers/mining.rs` test
    `getblocktemplate_renders_candidate_and_reuses_control_result`
  - `crates/rpc/tests/core_compat.rs` test `mining_responses_deserialize_into_pinned_types`
- `API-23`:
  - `crates/rpc/src/handlers/mining.rs` tests
    `prioritisetransaction_calls_mempool_prioritise_directly`,
    `prioritisetransaction_rejects_nonzero_dummy_like_core`,
    `prioritisetransaction_requires_fee_delta_as_third_parameter`,
      inline regression coverage for extra parameters and named fee_delta
    - Execution evidence: `cargo test -p bitcoin-rs-rpc prioritisetransaction` passes (run locally).
- `API-24`:
  - `crates/rpc/src/handlers/mining.rs` tests
    `prioritisetransaction_rejects_dust_outputs_like_core`,
    `prioritisetransaction_allows_dust_overlay_on_regtest`,
    `prioritisetransaction_allows_absent_txid_overlay`
  - `crates/mempool/src/standardness.rs` test `dust_relay_fee_changes_the_boundary`

- `API-25`:
  - `crates/rpc/src/handlers/mining.rs` tests
    `getmininginfo_omits_unset_optional_fields`,
    `getmininginfo_can_include_signet_challenge`,
    `getmininginfo_projects_control_state`

- `API-26`:
  - `crates/rpc/src/handlers/util.rs` tests
    `estimatesmartfee_rejects_conf_target_outside_core_range`,
    `estimatesmartfee_rejects_unknown_estimate_mode`,
    `estimatesmartfee_accepts_core_estimate_modes_and_rejects_trailing`
  - `crates/node/tests/overhaul_fee_history.rs` tests
    `empty_or_thin_history_answers_insufficient_data`,
    `real_confirmations_qualify_the_estimate`,
    `replacement_untracks_victim_without_false_confirmation`,
    `eviction_untracks_without_false_confirmation`,
    `reorg_reconfirm_records_exactly_one_observation`,

- `API-27`:
  - `crates/rpc/src/handlers/mining.rs` tests
    `generateblock_rejects_unknown_mempool_txid_like_core`,
    `generateblock_rejects_undecodable_raw_tx_like_core`,
    `generateblock_keeps_raw_transactions`

- `API-28`:
  - `crates/rpc/src/handlers/mining.rs` test
    `getprioritisedtransactions_projects_the_overlay`

- `API-29`:
  - `crates/rpc/src/handlers/mining.rs` tests
    `generatetoaddress_rejects_script_hex_and_descriptors`,
    `generateblock_rejects_garbage_output_like_core`,
    `generateblock_rejects_invalid_supplied_checksums`

- `API-30`:
  - `crates/node/tests/unit/mining/apply_error_tests.rs` tests
    `generateblock_validity_wraps_bip22_reason`,
    `generateblock_validity_keeps_shutdown_operational`
  - `crates/node/tests/mining.rs` test
    `generateblock_raw_tx_does_not_require_mempool_admission`
  - `crates/rpc/src/handlers/mining.rs` test
    `generateblock_maps_test_block_validity_to_verify_error`

- `API-31`:
  - `crates/rpc/src/handlers/mining.rs` tests
    `generateblock_rejects_multipath_before_ranged_like_core`,
    `generateblock_rejects_hardened_xpub_like_core`

- `API-32`:
  - `crates/rpc/src/handlers/mempool.rs` tests
    `gettxspendingprevout_projects_queries_and_removal_from_the_existing_index`
    and `gettxspendingprevout_rejects_argument_count_with_local_shape_errors`.
  - `bin/bitcoin-rs/tests/overhaul_process_harness.rs` module
    `spending_prevout_cases`: pinned Core 31.1 comparison of admitted,
    replaced, and confirmed spenders, ordered and duplicate requests,
    optional transaction bytes, named forms, and parameter errors.

## Vocabulary
