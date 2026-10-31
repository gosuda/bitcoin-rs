# External API contract

`API-01`–`API-35` govern RPC, REST, Esplora and ZMQ under the
[contracts precedence rule](README.md). The clauses below own each behavior.
[Verification boundaries](#verification-boundaries) distinguish current coverage from unverified comparisons.

The opt-in BIP352 `getblocktweaks` extension uses the retained-input owner below.
Its [service documentation](../silent-payments.md) owns the experimental RPC shape,
admission/publication checks, coverage limits and evidence. Complete scanning and
wallet interoperability remain unverified.

## Clauses

### `API-01`: Single manifest owner

- `REGISTRY` in `crates/rpc/src/registry.rs` is the single source of truth for RPC, REST and ZMQ. Each row binds one dispatch arm to one compatibility claim.
- `MANIFEST` in `crates/rpc/src/manifest.rs` projects those rows.
- A JSON-RPC method answers only when a non-`Unimplemented` row carries its name.
- No second route inventory exists.
- Each `Entry` carries `name`, `kind` (`Rpc`, `Rest`, `Zmq`), `status`, `feature`, `core_version`, `notes`, and `since`.
- Each `Entry` also carries required capabilities, error behavior, consistency class, resource budget, and evidence scenario.
- `Status` is `Supported`, `Deviation`, `Implemented (unverified)`, `Extension`, `Disabled`, or `Unimplemented`.
- `[reference].differential_harness` in `crates/rpc/core-compat.toml` gates `Supported`.
- Compatibility class, runtime readiness, and observed proof stay separate facts.
- Unsupported Core surfaces stay `Unimplemented` and answer `RpcError::MethodNotFound` (`-32601`).
- No wallet-only RPC is a disguised successful no-op.
- The build generates `docs/rpc-reference.md` from the registry. Maintainers MUST NOT edit that file by hand.
- `crates/rpc/tests/manifest_coverage.rs` enforces set equality between registry and live dispatch in both directions.
- The test regenerates the reference (`REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test suite manifest_coverage::regenerate_reference -- --ignored`).

### `API-02`: JSON-RPC mechanics and the wallet-free surface

- Parameter type and coercion rules follow the pinned Core 31.1 contract.
- Named and positional forms, declared JSON-RPC 1 and 2 envelopes, notifications, authentication, and error ordering also follow that contract.
- The server validates the envelope before dispatch (`crates/rpc/src/server.rs::handle_single_json`, mirroring `src/rpc/request.cpp`).
- A non-null `jsonrpc` field MUST be a string `"1.0"` (accepted legacy) or `"2.0"`.
- `params` MUST be an array, object, or `null`.
- `method` MUST be present and MUST be a string.
- An explicit-null `method` returns "Missing method", not "Method must be a string".
- An absent or explicit-null `jsonrpc` field selects the legacy dialect.
- Violations return `-32600` with Core's exact message, and the method never runs.
- A top-level non-object or non-array returns `-32700` ("Top-level object parse error", `src/httprpc.cpp` final `else`).
- HTTP status follows Core (`src/httprpc.cpp`).
- An envelope refusal returns `-32600` at HTTP 400 for any claimed dialect.
- A rejected `jsonrpc` field falls back to the legacy envelope.
- A `method` or `params` refusal after a clean `"2.0"` keeps the v2 envelope.
- On dispatch errors, the legacy dialect answers HTTP error status (`-32600`->400, `-32601`->404, else 500).
- The v2 dialect answers dispatch errors in HTTP 200.
- A batch with replies answers 200 with per-member errors.
- An empty batch answers 200 `[]`.
- An all-notification batch answers 204 with no body.
- Failures map through `RpcError` (`crates/rpc/src/error.rs`): `-32700`, `-32600`..=`-32603`, plus Core `-1`, `-3`, `-5`, `-8`, `-9`, `-10`, `-22`, `-25`, and `-26`.
- `createrawtransaction` consumes only `inputs`, `outputs`, `locktime`, and `replaceable`.
- The version stays 2, and `replaceable` defaults to false.
- A named `version` is unknown (`-8`).
- A fifth positional or `args`-prefix entry (including null) returns `-32602`.
- Duplicate, collision, and unknown-name validation precedes this arity check.
- The registry declares the deviation.
- Amounts are integer satoshis internally.
- Adapters render exact BTC / sat-per-vB.
- Shared transaction JSON reads raw version bits as unsigned 32-bit integers.
- Shared transaction JSON reads raw output amounts as signed 64-bit integers.
- `decoderawtransaction`, verbose `getrawtransaction`, and verbose block entries share that owner.
- `coinbase_tx.version` uses the unsigned conversion.
- Block header versions stay signed.
- Raw chain times appear only for positive confirmations.
- Native tx version is the unsigned wire value.
- Relative-lock rules compare unsigned values.
- Stored bytes remain unchanged.
- Missing contextual facts degrade a single input to its raw outpoint with one warning. Budget exhaustion and cancellation return errors.
- The node ships no wallet and holds no private keys.
- Key reveal, import, create, and use methods return `MethodNotFound`.
- Key-free `getdescriptorinfo`, `deriveaddresses`, `decodescript`, `scantxoutset`, `combinepsbt`, and `finalizepsbt` remain supported.
- `scantxoutset` is a bounded cancellable domain query, not wallet access.
- The getnodeaddresses call combines live peer registry entries and persisted addnode entries deduplicated by socket address. The call returns Core-format address objects.
- Verbose `getrawtransaction` uses the shared `tx_render::transaction_json` projection.
- Unsigned versions remain preserved across mempool, explicit-block, and txindex lookups.
- Inactive explicit blocks report zero confirmations and omit times.
- Mempool replies omit chain fields.
- Numeric verbosity 2 adds certified fees and input prevouts.
- Verbosity 1 or boolean true keeps the ordinary projection.
- Core script JSON has one projection owner in `tx_render.rs`.
- The owner formats decimal short pushes, malformed-instruction markers, checksummed inferred descriptors, and optional address or hex.
- Inputs alone decode defined sighash suffixes.
- Esplora keeps its separate opcode and push spelling.
- `decodescript` uses the native parser and script-validity predicates.
- Wrapper eligibility follows Core 31.1; P2WSH inference receives only its redeem script with no key provider.
- Parsed Miniscript enforces Core sanity checks, including sane unsatisfiable scripts.
- No second parser or signing state exists.
- `decodescript` accepts positional and named `hexstring`.
- Declared deviations include compact usage text for missing or extra arguments.
- Direct-call hex input has a limit equal to the 16 MiB HTTP body budget.
- Address-descriptor fallback applies when complex Miniscript carries an invalid-curve key rejected by the parser.
- Core infers `wsh(...)` in that case; the fallback keeps the same script, addresses, and wrappers.
- Bare P2PK/multisig keeps Core syntactic key handling.
- This is an input and work limit, not a response-size limit.
- Pinned matrix: `overhaul_process_harness::script_decode_cases` (classes, encodings, wrappers, checksums, params, networks, shared projections).
- `gettxoutproof` without `blockhash` requires an enabled txindex whose capability is ready.
- Without an enabled txindex, it answers Core `-8` (`The transaction index must be enabled to get a proof`) and reads no block body.
- With `blockhash`, it reads only that block.
- Both forms hold one blocking-quota slot (`API-34`) and poll the request latch.
- The registry declares `Blocking`.

#### Retained block inputs

- `getblock` verbosity 2/3, `getrawtransaction` verbosity 2 and `/rest/spenttxouts` share one read-only `utxo::contract::BlockUndoSource` implemented by the chainstate owner.
- RPC captures one `AppliedView` for confirmations/next-block linkage and passes its hash.
- A moved applied hash, durable receipt (including archive-only commits), or expired retention lease refuses the response.
- An in-flight prune reservation provisional error requires consumers to wait and retry instead of rebuilding.
- No new availability store or generation counter exists.
- Successful undo is complete and input-ordered.
- Same-block inputs come from earlier transactions in the authenticated body.
- External inputs come from native net undo.
- BIP30 overwritten-output restores are not input rows.
- The implementation uses no present-day UTXO lookup and no invented coin.
- The native version-1 undo format is unchanged.
- A retained body with uncertified or pruned undo MAY omit fee and prevout fields in `getblock` and `getrawtransaction`.
- REST reports undo unavailable in that case.
- Missing or unreadable expected undo is a typed error, never an empty success.
- A missing body under a granted lease is `HistoryUnavailable::Missing` and transient (REST 503).
- Pruned bodies and undo stay unavailable.
- Genesis has one empty spent-output row without an undo record.
- `getblock` still requires its real retained body for genesis.
- REST binary and hex formats encode a CompactSize transaction count, then per-input counts, then ordinary serialized TxOuts.
- The disk undo encoding is never exposed.
- JSON rows carry value and scriptPubKey.
- Verbosity 3 adds generated and height to per-input prevouts.
- Verbosity 2 gains fees without prevouts.
- Coinbase fee and prevout fields stay omitted.
- Transaction JSON uses the shared wire projection (unsigned high-bit versions).
- Stale headers omit the successor hash of the competing branch, matching Core.
- `getrawtransaction` verbosity 2 pairs the requested transaction with its block row for explicit-block or txindex lookups (fees plus prevouts).
- Mempool and coinbase replies omit both fees and prevouts.
- Explicit-block `getrawtransaction` verbosity 2 authenticates the whole block and input view before selecting the transaction, including a requested coinbase.
- An expected missing or corrupt undo therefore fails that coinbase lookup as well.
- Verbosity 1 or boolean true and implicit txindex coinbase lookups do not require undo.
- This conservative availability deviation from Core's coinbase shortcut keeps the certified reader authoritative.
- Declared deviation: after a later branch receipt replaces the retained undo extent, older stale rows lack current certification.
- Those older stale rows omit undo fields even if raw rows remain.
- Snapshot history is unavailable until its archive receipt certifies it.
- Transient absence and explicit resource limits can return retry responses, unlike Core.
- `/rest/block` keeps its separate projection without undo fields.
- Full block REST rendering, spent outputs, detailed `getblock`, and verbosity-2 block reads share two materialization permits.
- Body copies are bounded to 4,000,000 bytes.
- Undo copies are bounded to 64 MiB.
- Undo counts are bounded by the authenticated block and remaining record bytes.
- Script lengths MUST fit the record before allocation.
- Spent-input rows derive from that block.
- Each spent script is copied once from the bounded body or undo.
- These bounds cover input materialization only, not heap or JSON expansion.
- Format-specific budgets belong to the renderer, not `BlockUndoSource`.
- Certification shares a 4,096-parent-hop budget reusing the trusted height index.
- Retained-body witness checks reuse the bounded deployment query.
- An off-header-chain BIP9 read captures at most 2,000,000 ancestor IDs (at most 8 MB).
- Both budget failures are explicit resource limits, not throughput claims.
- A txindex hit for non-coinbase verbosity-2 still decodes the complete body plus retained undo.
- It then searches the block for its row under the shared render permit.
- Performance qualification (bytes, decode cost, latency, permit refusals, single or concurrent load) follows `docs/benchmarks/README.md`.
- No measurement claim is established here.
- Storage boundaries provide bounded reads with safe unsupported defaults, never an unbounded fallback.
- These include Fjall value checks, redb read guards, and RocksDB pinned values before the owned copy.
- Backend pages, caches, and decompression remain outside the copy bound.
- Block reads bound locator and frame length before allocation.
- Custom stores MUST implement the bounded reads before serving this capability.

#### Block database verification

- One owner verifies: `chainstate::verify::verify_recent_blocks` serves both the `verifychain` RPC (through node-owned chain control) and the startup check.
- The walk follows parent links back from the applied tip, excluding genesis.
- Defaults are level 3 and six blocks.
- Nonpositive depth means every block above genesis.
- Larger depths clip to the applied height.
- Both parameters are Core signed 32-bit values.
- Absent or null means default.
- A non-number is a type error.
- An out-of-range number is out of range.
- Levels clamp to 0–4.
- Every requested body is read and decoded, including level 0, and its header MUST hash to the named block.
- Levels 1–4 additionally check header proof of work.
- Corrupt, malformed, truncated, mismatched, invalid-work, or failed-Merkle inputs return `false`.
- Level 1 reuses consensus context-free body checks: coinbase placement and scriptSig bounds, nonempty inputs and outputs, money ranges, null or duplicate inputs.
- It also checks the 1,000,000-byte stripped limit and aggregate legacy sigop cost.
- Failure returns `false` even with valid header, PoW, and Merkle root.
- RPC keeps no copy of those rules.
- Core `CheckBlock` (`src/validation.cpp`) excludes witness commitments, full witness weight, finality, and UTXO or script execution.
- Level 1 also excludes those checks: a witness-only mutation still passes.
- The walk retains only the current block.
- Level 2 additionally reads and decodes each undo record against its block.
- The copy bound covers serialized block size, input and output counts, spendable-script limit, and codec overhead.
- The separate 64 MiB consumer-query budget does not limit verification.
- Levels 3–4 run the level-2 checks without disconnect and reconnect replay.
- A history lease pins the window against concurrent pruning and is released at the end.
- History this node never kept or intentionally no longer keeps ends the walk as skipped once held blocks pass.
- This includes history below executed prune lines, in-flight claims, history below assumed-valid snapshot bases, bodyless stores, and withdrawn pins.
- Shutdown skips instead of failing.
- The answer is `true` only when every window block was checked and passed.
- Damaged blocks, damaged undo records, and windows reaching unheld history (pruned, snapshot-only, unreadable, missing bodies) answer `false`.
- Upstream `-1` for unavailable data stays out; one owner keeps the boolean mapping.
- Cancellation and recovery closure return `-1` errors, distinct from that boolean.
- A triggered latch answers `-1` (`Block verification interrupted`).
- Chainstate closed for recovery answers `-1` (`Chainstate is unavailable for verification`), including mid-walk, final-read, and empty-window closures.
- Boundary poll order is cancellation, recovery closure, shutdown, then history pin.
- Mid-walk shutdown still skips to `false`.
- No requested block is silently passed.
- The walk holds no tree or chain-transition guard during body reads (applied ancestor bodies and undo records are immutable).
- A request arriving after its handler stopped reports `-1` before touching state.
- The same latch is polled at every progress boundary and before success.
- Closed-for-recovery is fail-closed at the same boundaries, including the empty window.
- The existing blocking-call budget applies.
- This is a read-only integrity check: it never changes the UTXO set, rewrites bodies, repairs storage, or advances a durable root.
- Startup verifies the last six applied blocks one level stronger than any RPC level.
- Startup adds header-body binding including the witness commitment, and refuses to open on damage, naming the block.
- Verification repairs nothing.
- Signet challenge validation and level-3/4 disconnect and reconnect verification remain outside `verifychain`.
- `Deviation` stays in the registry for those omissions.
- Excess arguments keep the local `-32602` shape error.

#### Native deployment reporting

- `getdeploymentinfo` and `/rest/deploymentinfo` share one typed projection of `chain::deployment_statuses` and consensus `verify_flags`.
- The default hash is captured from one applied publication.
- Explicit hashes select any known header ancestry, including side branches and headers without bodies.
- `active` describes enforcement for the next block.
- BIP9 `status`, `since`, and signalling describe the queried block.
- `status_next` describes its successor.
- Script flags describe the queried block.
- Unavailable optional fields are omitted, never rendered null.
- Header-chain lookups reuse the height index.
- An off-header-chain BIP9 query captures at most 2,000,000 ancestor IDs once (at most 8 MB).
- The query then uses direct lookup with the existing state machine and cache.
- Larger side histories return RPC `-1` / REST 503.
- This is a work bound, not a performance claim.
- Declared Core deviation, not a consensus change: native CSV and Segwit use historical BIP9 on mainnet/testnet3.
- Native Taproot uses a fixed height.
- `testdummy` is not configured.
- Fixed regtest heights and Segwit on testnet4/signet differ from Core 31.1.
- Historical script flags report native validation flags including BIP16 exceptions, not Core retroactive WITNESS/TAPROOT flags.
- Full deployment parity remains open.
- Unknown RPC hashes return `-5`.
- Malformed hashes return `-8`.
- REST keeps its JSON-only format with 400 for malformed or unknown hashes.
- Excess arguments keep the local JSON-RPC parameter-shape error, not Core help text.
- Envelope proof: `crates/rpc/src/server.rs` envelope and batch tests plus `crates/rpc/tests/auth.rs` legacy-envelope pin.
- Pinned Core sources: `src/rpc/request.cpp`, `src/httprpc.cpp` (rules read from pinned source, no Core binary run).

### `API-03`: REST dialect

- REST keeps its own HTTP semantics in `crates/rpc/src/rest.rs` (status codes, content types, empty bodies, not-found).
- No generic JSON-RPC error handler spans the dialects.
- Formats are `json` (`application/json`), `hex` (`text/plain`), and `bin` (`application/octet-stream`).
- A disabled gateway or unknown path returns 404.
- Malformed parameters return 400.
- Unknown hashes are handled per route: headers return an empty 200, spent outputs return 404, and deployment queries return 400.
- `/rest/getutxos` GET URI input and POST binary or hex input share one authoritative UTXO and mempool lookup.
- POST reads a bool plus canonical CompactSize outpoint vector directly, limited to 15 outpoints and a 2048-byte wire body before allocation.
- JSON bodies, mixed input sources, malformed or trailing data, and oversized requests fail with HTTP 400.
- Empty serialized vectors are valid; URI requests still require outpoints.
- Plain coin reads capture tip and coins under the stable chain read role.
- Mixed reads retain one pool view and reject a changed or odd chain generation.
- Rendering happens after guards are dropped.
- Pool-created outputs use Core REST `MEMPOOL_HEIGHT` (2147483647).
- The canonical POST decoder intentionally corrects Core 31.1's string-length-prefix bug.
- The registry retains `Deviation`.
- Independent wire fixtures plus same-tip Core GET establish the intended bytes.
- Core POST's measured different answer is an explicit known gap.

### `API-04`: ZMQ notification contract

- `crates/rpc/src/zmq.rs` owns declared Core topics `hashblock`, `hashtx`, `rawblock`, `rawtx`, and `sequence`.
- It preserves Core byte order, sequence counters, and connect, disconnect, and mempool ordering.
- The `sequence` body frame is reversed txid (32 bytes) + label byte (1) + little-endian sequence (8): 41 bytes total.
- `BlockInclusion` emits no `R` frame; every other removal reason does.
- The implementation emits one event per change, in commit order (`MPL-03`).
- Delivery is bounded and optional.
- Queue overflow records a sticky gap plus reconcile signal instead of growing memory.
- High-water marks stay per endpoint (`DEFAULT_ZMQ_HWM = 1_000`).
- Canonical estimator and relay accounting is never dropped (`MPL-04`).

### `API-05`: Solo-mining generate path

- Owner: `MiningControl::generate` (`crates/mining/src/control.rs`) via `MiningCoordinator::generate` (`crates/node/src/mining.rs`), assembling each block through `MiningService::assemble_fresh`.
- Each block is a fresh candidate (no GBT cache).
- `generateblock` validates the unsolved block first (`API-30`).
- Both generate paths solve and then either submit through the chainstate owner or dry-validate through `Chainstate::validate_block` (`ARCH-07`).
- Persistence and tip advancement are conditional on `submit`.
- Each submitted block is a separate commit: an error after *N* successes leaves those *N* blocks durable.
- Callers retry after reading the applied tip.
- `nblocks` is uncapped; the result vector grows one block at a time.
- `generatetoaddress` accepts only a network-valid address, uses mempool package selection, collects fees, and always submits.
- `generateblock` accepts an address or descriptor (`require_checksum = false`; a supplied checksum is verified).
- Ranged and multipath descriptors are refused (`API-31`).
- The transactions array is required (explicit `[]` is coinbase-only).
- Listed order is kept; listed fees are not added to the coinbase.
- A 64-character hex string is a mempool txid.
- Decoded raw transactions are included without mempool admission.
- Raw-tx sigop costs use copied applied-chain prevouts plus earlier listed-transaction outputs with candidate witness activation.
- These costs are captured under the chain read fence and computed after lock release.
- Missing inputs still pass to authoritative validation.
- Extra positional arguments are rejected.
- Output parse errors are `API-29`; pre-nonce consensus failures are `API-30`.

### `API-06`: `getnetworkhashps` snapshot and invalid-height behavior

- Owner: `network_hash_ps` in `crates/mining/src/network_hashps.rs`.
- The node coordinator supplies only the locked block tree and one applied-tip snapshot.
- Height checks and the hash-rate walk use that snapshot plus locked tree, never a second tip load.
- The window is Core's parent walk (`lookup` parent pointers from the resolved start, min/max header time, `chainwork` delta).
- Heights are not re-resolved through `node_at_height_from`.
- `nblocks` (`lookup`) MUST be positive or `-1` (since last retarget), else Core `-8` (`Invalid nblocks. Must be a positive number or -1.`).
- `height` MUST be `-1` (snapshot tip) or an existing applied-chain height on that snapshot.
- Below `-1`, above the tip, or in-range-but-unwalkable heights return Core `-8` (`Block does not exist at specified height`), not a zero rate.
- An empty chain with `height == -1` estimates `0.0`.
- `getmininginfo`'s `networkhashps` is best-effort from the tip and skips this error path.

### `API-07`: RPC fixture reference provenance

- Owner: the corpus loader in `crates/rpc/tests/support/fixture.rs` owns `core_version` and `core_binary_sha256` pins and their validation.
- Every fixture records the version and exact binary digest of its capture.
- Missing, empty, or mismatched values fail loading before replay.
- The pins describe the released Core node used for recorded responses.
- They are separate from the `bitcoinkernel` oracle and the `MANIFEST` family (`API-01`).
- Reference refreshes MUST update constants and affected fixtures together.
- The loader only checks that `provenance.evidence` is non-empty; it does not retrieve or authenticate it.
- `core_parity` replays recorded responses against bitcoin-rs without executing or hashing a local `bitcoind`.
- Fixture metadata does not attest source commit or build config.
- Process-binary verification and missing identities remain open under #625 and #626.

### `API-08`: Bounded public exposure

- Administrative RPC stays private and authenticated by default.
- Public read and broadcast exposure, allowed hosts and origins, and rate and concurrency limits are independently configured.
- A JSON-RPC batch accepts at most 1,000 elements.
- A larger batch is refused with `-32600` (`Batch size limit exceeded`) before any member runs.
- The element cap supplements the 16 MiB body limit, which alone would admit about 490,000 minimal members.
- `gettxoutsetinfo` holds one bounded blocking-quota slot (`API-34`) and one shared UTXO-wide scan reservation, the same reservation `scantxoutset` uses.
- A second call is refused with `-8` (`a UTXO-wide scan is already running`), and a running `scantxoutset` also refuses it with `-8`.
- The walk holds the UTXO stable-view read guard for its whole duration, so block commits wait for it.
- The single reservation and blocking quota bound that wait to one caller per dispatcher.
- The request latch interrupts it with `-1`.
- Request bodies, batch size, response assembly, scan rows, in-flight work, and long-poll clients are bounded.
- A public explorer read cannot consume the CPU or memory quota needed to validate new blocks.

### `API-09`: Esplora dialects

- `/api` exposes the public Esplora (electrs) contract; `/esplora` is the versioned mempool-backend superset.
- Both project the same node and index state; neither is a separate mode or database and no electrs proxy exists.
- `/api` is closed: requests inside it never fall through to JSON-RPC.
- Unprefixed electrs paths return 404 so JSON-RPC keeps `/`.
- `/api/v1` belongs to the external mempool application's own API, not this node.
- The backend dialect additionally requires `GET /internal/mempool/txs`, `GET /internal/block/{hash}/txs`, `POST /internal/txs`, `POST /internal/mempool/txs`, batched outspends `POST /internal/txs/outspends/by-txid` and `by-outpoint`, and address summaries.
- Only declared backend routes exist; each route is marked as such.
- History reads use bounded pages and cursors preserving public Esplora cursor semantics.
- Cursors are the exact lowercase `txid` display text.
- Malformed, noncanonical (including uppercase or prefixed), unknown, and missing cursors restart from the beginning.
- A valid known cursor strictly excludes it and earlier entries.
- Lag, reorg, or disabled capability returns the declared unavailable response, never an empty success.
- `/txs/chain[/<last_seen_txid>]` reads are bounded to the requested page (up to 25 items).
- Confirmation, block metadata, and transaction projections hydrate only the page slice, never the full history.
- Pruned or absent unselected older blocks do not fail earlier pages.
- Chain queries do not enumerate `ScriptLive` UTXOs or query mempool state.
- Sentinel `last == Some("")` (`/txs/mempool`) resolves mempool activity directly from locators without scanning history or taking block-metadata locks.
- Index refusals map by cause: `Retry`/`Unavailable` (lag, reorg, disabled capability, missing/pruned body) are 503; `Storage` (failed/corrupt body read, corrupt index row) is 500.

### `API-10`: Broadcast and preview through the admission gateway

- `sendrawtransaction`, `submitpackage`, `testmempoolaccept`, Esplora `POST /tx`, and P2P ingress reach the single `MempoolGateway` (`POL-02`).
- Each committing producer carries an explicit `AdmissionOrigin` and its own request fee limits.
- Scoped `submitpackage` admits singletons and 1p1c through the atomic package owner with Core individual-first partial results (`POL-05`).
- Wider shapes and replacement are refused.
- Named and positional `package`, `maxfeerate`, and `maxburnamount` feed the same owner; burn guards run before mutation.
- Esplora `POST /tx` exists on both `/api` and `/esplora` with `AdmissionOrigin::Esplora` and a fixed 10,000,000 sat/kvB request ceiling.
- Its hex body provides no fee override.
- RPC keeps its own default plus `maxfeerate` override; peer ingress has no request cap.
- The gateway owns fee verification and authoritative mutation.
- Preview runs the identical pipeline and mutates nothing (no membership, estimator, relay, admission sequence, or victims; `POL-06`).
- `testmempoolaccept` returns preview rows in the frozen Core 31.1 shape with frozen reject-reason strings.
- Broadcast rejections map to the Esplora dialect: a rejected transaction is a 400 with the reason, not a retryable 503.
### `API-11`: BIP22/BIP23 template extras

- Owner: `template_from_candidate` in `crates/mining/src/coordinator.rs` via `MiningService::get_block_template`.
- JSON projection: `render_block_template` in `crates/rpc/src/handlers/mining.rs`.
- Capabilities are the producer's implemented set (`proposal`, `longpoll`).
- Client-advertised names are not echoed back.
- `submitold` and `workid` are unmodeled BIP23 extras and are never emitted.
- On signet, the template carries `signet` in `rules` (mandatory) and `signet_challenge`.
- `signet_challenge` is the default challenge owned by `Network::signet_challenge`.
- Other networks omit `signet_challenge`.
- `longpollid` is `{tip_be_hex}{mempool_sequence}`.
- It includes `:{fee_delta_sequence}` when the fee-priority revision is nonzero.
- An id without the suffix means fee revision zero.
- Malformed ids (including invalid UTF-8 split boundaries) are rejected without panicking.
- A successful `prioritisetransaction` publishes a new fee generation.
- The next template keeps tip and membership, advances the fee component, and wakes long-poll waiters with that id.
- Admissions invalidate older membership generations and wake long-polls.
- The next template read captures membership and fee revisions together.
- `getblocktemplate` never carries a coinbase budget.
- Typed `BlockTemplateRequest.coinbase_budget` is `None` for every RPC request.
- Only the typed `MiningControl` embedder (experimental SV2 regtest adapter in `tools/stratum-sv2`) sets it.
- A budgeted candidate leaves that room in the coinbase with a budget-qualified id.
- The ordinary candidate is used when it already admits the budget.
- The qualifier is not RPC contract: RPC callers never receive it, and long-poll waits compare generations only.

### `API-12`: Mainnet template operational gates

- Owner: `ensure_template_ready` in `crates/rpc/src/handlers/mining.rs`.
- Template mode on mainnet requires at least one live peer in `PeerTable`.
- Template mode on mainnet also requires leaving IBD (`!ctx.chain.ibd.is_active(now, network)`, latch in `crates/chain/src/ibd.rs`).
- Failures return Core `-9` (`bitcoin-rs is not connected!`) and `-10` (`bitcoin-rs is in initial sync and waiting for blocks...`).
- Proposal mode skips these gates.
- Non-mainnet networks skip these gates (Core `IsTestChain()`).

### `API-13`: `submitheader`

- Owner: `MiningCoordinator::submit_header` in `crates/node/src/mining.rs`.
- RPC decodes hex and projects the result; it does not admit headers.
- Reject projection is `header_reject_reason` in `crates/mining/src/bip22.rs`.
- Authoritative admission is `Chainstate::admit_headers`.
- Decode failures (invalid hex, fewer than 80 bytes) return Core `-22` (`Block header decode failed`).
- Extra bytes after an 80-byte header are ignored (Core `DecodeHexBlockHeader`).
- For an unknown header, the previous header MUST already be in the block tree.
- An empty tree admits the network genesis root.
- Otherwise, the call returns `-25` (`Must submit previous header (HASH) first`) before PoW validation, including invalid targets.
- Admission uses `accept_headers`, the same gate as inbound P2P headers.
- Known-valid duplicates (including genesis) succeed.
- Known-invalid duplicates return `-25` (`duplicate-invalid`).
- Extending node-marked-invalid returns `-25` (`bad-prevblk`).
- Other invalid headers return `-25` with Core reasons (`high-hash`, `bad-diffbits`, `time-too-old`, `time-too-new`, `bad-version(0x%08x)`, `time-timewarp-attack`).
- Success is JSON `null`.
- Header-only admission does not apply the block or publish a mining generation.

### `API-14`: GBT client-rule negotiation

- Owner: `ensure_client_rules_for_template` and `ensure_client_supports_mandatory_rules` in `crates/rpc/src/handlers/mining.rs`.
- Template mode requires the client to list `segwit`.
- On signet, template mode also requires `signet`.
- Failures return Core `-8` with Core exact messages (`getblocktemplate must be called with the segwit rule set ...`, `... signet rule set ...`).
- Signet is checked first (Core v31.0 `src/rpc/mining.cpp`).
- Checks run before assembly; proposal mode skips them.
- After assembly, any remaining mandatory template rule the client omitted returns Core `-8` (`Support for 'NAME' rule requires explicit client support`).

### `API-15`: `submitblock` decode

- Owner: `decode_submitted_block` in `crates/rpc/src/handlers/mining.rs`.
- Admission stays on the single `MiningControl::submit_block(BlockPayload)`.
- The decoder hex-decodes the input and runs one shared decode via `BlockPayload::from_prefix`.
- It retains only the consumed prefix and discards the remainder.
- Invalid hex or an incomplete block returns Core `-22` (`Block decode failed`, Core `DecodeHexBlk`).
- Extra bytes after a complete block are ignored.
- This decoder is the cooked external boundary, and its bytes are not the exact request payload.
- A second dummy argument is accepted and ignored (BIP22).
- A third argument returns JSON-RPC `-32602`.

### `API-16`: GBT proposal request parsing

- Owner: `parse_block_template_request` in `crates/rpc/src/handlers/mining.rs`.
- An unknown or non-string `mode` returns Core `-8` (`Invalid mode`).
- Proposal does not require listing the `proposal` capability.
- Missing `data` returns Core `-3` (`Missing data String key for proposal`) with no `invalid type:` prefix.
- Decode uses `decode_submitted_block` (`API-15`): `-22` `Block decode failed`, leftover bytes ignored.
- Proposal consumes the decoder output via `payload.into_block()` into `Proposal`, discarding retained bytes.
- It dry-validates and never persists.

### `API-17`: `submitblock` uncommitted witness nonce

- Owner: `update_uncommitted_block_structures` in `crates/mining/src/coinbase.rs`, called from `MiningCoordinator::submit_block` in `crates/node/src/mining.rs`.
- The miner applies read-only fill-need signals on the borrowed payload and submits directly when no fill applies (no re-encode/clone).
- Only a possible fill trial-clones and submits `from_local` of the filled clone.
- The previous header must be known, and SegWit must be active for the height.
- If the coinbase has a BIP141 commitment output and its witness is empty, `submitblock` inserts the 32-byte reserved nonce (Core `UpdateUncommittedBlockStructures`).
- An existing coinbase witness is left unchanged.
- Proposal mode does not fill.

### `API-18`: `submitblock` and proposal duplicate vocabulary

- Owner: `MiningCoordinator::known_block_result` in `crates/node/src/mining.rs`.
- GBT proposal looks the hash up first (Core `LookupBlockIndex`).
- A connected scripts-valid body returns `duplicate`.
- An `Invalid` block returns `duplicate-invalid`.
- Any other tree entry (including a header-only tip) returns `duplicate-inconclusive`.
- `submitblock` matches Core v31 `ProcessNewBlock`: a previously connected scripts-valid body (including after a later reorg) is `duplicate`.
- A header admitted by `submitheader` still receives the body.
- Duplicate classification holds the chain-transition lock through apply.
- Concurrent submissions of one body cannot race into a previous-tip refusal.

### `API-19`: BIP22 reject reasons

- Owner: `bip22_reject_reason` in `crates/node/src/mining.rs` for `ApplyError` arms, delegating to `consensus_reject_reason` and `chain_reject_reason` in `crates/mining/src/bip22.rs`.
- Proposal and `submitblock` project apply and consensus failures as Core `GetRejectReason` strings (`bad-cb-missing`, `bad-txnmrklroot`, `bad-cb-amount`, `high-hash`, `time-too-old`, ...).
- Operational refusals (`Shutdown`, journal backpressure) stay `inconclusive`.
- The first failing check names the reason.
- Context-free checks run in Core `CheckBlock` order: merkle root and mutation, size limits, coinbase placement, transaction checks, then legacy sigops.
- Witness malleation and block weight run after them, in Core `ContextualCheckBlock` order.
- Owner: `verify_block_rules_precomputed` in `crates/consensus/src/verify_block.rs`.
- A body without a coinbase holding a 64-byte witness-stripped transaction is a mutated body, not an invalid header, and still projects `bad-cb-missing`.
- A signet block failing BIP325 solution is `bad-signet-blksig`, checked at commit after block rules and not by proposal mode.
- Storage, UTXO, durable-head, and internal-verifier failures propagate as `MiningControlError::Failed`, never as BIP22 rejection (same for `generateblock` prevalidation).
- Consensus `Display` remains log text; this mapping is the BIP22 wire owner.

### `API-20`: GBT `vbrequired` is always 0

- Owner: `template_from_candidate` in `crates/mining/src/coordinator.rs` via `MiningService::get_block_template`.
- Signalling deployments read from the applied tree through the node `ChainContextSource`.
- Core v31 hardcodes `vbrequired` to 0.
- Signalling deployments still appear in `vbavailable`.
- Locked-in bits are not OR'd into `vbrequired`.
### `API-21`: BIP141 witness malleation reasons

- Owner: `check_witness_malleation` in `crates/consensus/src/verify_block.rs`.
- Core `CheckWitnessMalleation` distinguishes three BIP22 strings.
- Commitment present with coinbase witness not a single 32-byte element maps to `bad-witness-nonce-size`.
- Commitment present with well-formed nonce but hash mismatch maps to `bad-witness-merkle-match`.
- Witness data without a commitment, or before SegWit, maps to `unexpected-witness`.
- Proposal does not fill an omitted nonce (`API-17` is `submitblock`-only).
- Therefore, an empty coinbase witness with a commitment returns `bad-witness-nonce-size`.
- `bip22_reject_reason` maps the consensus variants.
- Consensus `Display` remains log text.

### `API-22`: GBT `coinbaseaux.flags` is empty hex

- Owner: `render_block_template` in `crates/rpc/src/handlers/mining.rs`.
- Core v31 emits `coinbaseaux: { "flags": HexStr(COINBASE_FLAGS) }`.
- The flags bytes are empty, so the hex string is `""`.
- An empty object is not the Core shape.

### `API-23`: `prioritisetransaction` dummy and `fee_delta`

- Owner: `prioritisetransaction` in `crates/rpc/src/handlers/mining.rs`.
- Core reads `fee_delta` from params[2].
- The deprecated dummy (params[1]) MUST be omitted, null or numeric zero.
- Any other value returns `-8` (`Priority is no longer supported, dummy argument to prioritisetransaction must be 0.`).
- Two-argument calls do not treat params[1] as `fee_delta`.

### `API-24`: `prioritisetransaction` refuses pooled dust

- Owner: `prioritisetransaction` in `crates/rpc/src/handlers/mining.rs`.
- Core v31 rejects a mempool transaction with dust outputs when `require_standard` is set.
- That rejection returns `-8` (`Priority is not supported for transactions with dust outputs.`).
- `require_standard` follows Core's `-acceptnonstdtxn` default (enforced everywhere except regtest).
- Absent txids (fee-delta overlay only) are not checked.
- Dust detection uses the pool dust-relay fee via `tx_has_dust_outputs`.
- The wallet-facing subset of this surface (tip, fees, address/script queries, Esplora broadcast, key-free node RPCs) is owned by [wallet-facing.md](wallet-facing.md).

### `API-25`: `getmininginfo` omits unset optional fields

- Owner: `render_mining_info` in `crates/rpc/src/handlers/mining.rs`.
- Core pushes `currentblockweight`, `currentblocktx`, and `signet_challenge` only when set.
- Unset optional fields are omitted, not JSON `null`, via `typed_to_sonic_omitting_nulls`.

### `API-26`: `estimatesmartfee` parameters and Esplora fee estimates

- Owners: `estimatesmartfee` in `crates/rpc/src/handlers/util.rs`.
- Esplora owner: `/fee-estimates` in `crates/rpc/src/esplora/public.rs`.
- `conf_target` MUST be in `1..=1008` (Core `MAX_CONFIRM_TARGET`), else `-8` (`Invalid conf_target, must be between 1 and 1008`).
- `estimate_mode` is optional case-insensitive `UNSET`/`ECONOMICAL`/`CONSERVATIVE` (Core `FeeModeFromString`).
- Unknown strings return `-8` (`Invalid estimate_mode parameter, ...`).
- Non-strings return `-3`.
- Accepted modes are parsed only; the estimator does not split ECONOMICAL/CONSERVATIVE.
- The estimator horizon is 25 blocks (`MAX_CONF_TARGET = 25`).
- Larger `conf_target` values are answered with the 25-block rate.
- Insufficient data omits `fee_rate` and returns `errors: ["Insufficient data or no feerate found"]`.
- Trailing parameters are refused.
- Esplora `/fee-estimates` captures targets `1..=25`, `144`, `504`, `1008` from one mempool read view.
- This capture avoids mixed estimator states; the guard is released before formatting.
- It uses the same estimator and `sat_to_btc` projection multiplied by `100_000` to sat/vB.
- Targets without history are omitted.

### `API-27`: `generateblock` txid and raw-tx parse errors

- Owner: `parse_generateblock_transactions` in `crates/rpc/src/handlers/mining.rs`.
- A 64-character hex string is Core `Txid::FromHex`.
- A txid missing from the mempool returns `-5` (`Transaction {str} not in mempool.`, caller's string).
- Anything else is Core `DecodeHexTx`.
- Invalid hex or an incomplete transaction returns `-22` (`Transaction decode failed for {str}. Make sure the tx has at least one input.`).

### `API-28`: `getprioritisedtransactions` `modified_fee` is satoshis

- Owner: `getprioritisedtransactions` in `crates/rpc/src/handlers/mining.rs`.
- Core mining RPCs use satoshis, not BTC.
- `fee_delta` is an integer satoshi overlay.
- `modified_fee` (actual fee plus delta, present only when `in_mempool`) is the same unit.
- It is a JSON number in satoshis (Core `CAmount`).

### `API-29`: generate invalid-output text

- Owners: `generateblock_payout_script` in `crates/rpc/src/handlers/util.rs`; `generatetoaddress` in `crates/rpc/src/handlers/mining.rs`.
- `generatetoaddress` refuses a non-address with `-5` (`Error: Invalid address`).
- `generateblock` tries a descriptor first (`require_checksum = false`).
- Ranged and multipath descriptors return `-8` (`API-31`).
- On parse failure, the text is tried as an address.
- A miss returns `-5` (`Error: Invalid address or descriptor`, Core `src/rpc/mining.cpp`).
- A failing supplied checksum is refused through that fallback, not `CheckChecksum` wording.

### `API-30`: `generateblock` `TestBlockValidity` before solve

- Owner: `MiningCoordinator::generate` in `crates/node/src/mining.rs`.
- Core v31 `generateblock` runs `TestBlockValidity` with `check_pow = false`, `check_merkle_root = false` before `GenerateBlock`.
- Failure returns Core `-25` (`TestBlockValidity failed: {reason}`) where `{reason}` is the BIP22 `GetRejectReason` string (`API-19`).
- This pre-check applies only to `Ordered` selection (`generateblock`).
- An ordered candidate refused by the mining sigop preflight also returns this `-25` (`bad-blk-sigops`), not an operational `Failed`.
- `generatetoaddress` (`Mempool`) matches Core `generateBlocks` and skips it.
- The check calls `apply::validate_block` directly (`ApplyIntent::Propose` already skips hash-meets-target), not GBT `propose` (`API-18` vocabulary).
- Shutdown and journal backpressure stay `Unavailable`, not `TestBlockValidity`.
### `API-31`: `generateblock` multipath, ranged, and Expand errors

- Owner: `generateblock_payout_script` in `crates/rpc/src/handlers/util.rs`.
- Core `getScriptFromDescriptor` throws before the address fallback.
- More than one parsed descriptor returns `-8` (`Multipath descriptor not accepted`).
- `IsRange()` returns `-8` (`Ranged descriptor not accepted. Maybe pass through deriveaddresses first?`).
- An `Expand(0)` failure returns `-5` (`Cannot derive script without private keys`).
- Multipath is checked first (Core `descs.size() > 1` before `IsRange()`).
- A descriptor that is both reports the multipath error.

### `API-32`: `gettxspendingprevout` mempool snapshot

- Owner: `Mempool::outpoint_spender` owns the spending-index lookup and its typed consistency failure.
- The adapter validates all inputs before taking one gateway read guard.
- It captures spending references for every outpoint under the guard, and serializes after release.
- Results preserve query order, duplicates, and caller `txid` spelling.
- A row without a mempool spender carries only `txid`+`vout`.
- No confirmed-spend history is queried.
- Positional and named `outputs` and `options`, flattened named options, and the `args` prefix accept Core 31.1's `mempool_only` and `return_spending_tx`.
- Default is mempool-only; requested `spendingtx` uses full consensus serialization including witness.
- With `mempool_only=false`, a missing mempool spender fails with Core `-1` unavailable-txospenderindex error.
- An inconsistent index becomes an internal error, never an unspent result.
- Empty lists, strict object keys, txid syntax, and signed 32-bit nonnegative `vout` follow the pinned reference.
- After successful named binding, missing outputs and excess positionals keep local `-32602`.
- Core uses `-1` help for no-arguments and excess-arity, but `-3` for an outputs hole created by named options.
- Native keeps its missing-outputs error there; explicit null matches Core `-3`.
- Duplicate and unknown names, option conflicts, and positional/named collisions keep Core earlier `-8` errors.
- Overlong `args` prefixes also return those errors.
- The registry declares these validation deviations.
- Handler state is O(requested outputs).
- It never scans or clones the full mempool.

### `API-33`: Core snapshot import, export and lifecycle reporting

- `loadtxoutset(path)` synchronously reads an unmodified Core v2 `dumptxoutset` file.
- Positional `[path]` and named `{ "path": path }` are accepted.
- Relative paths resolve below the datadir.
- Input MUST be a regular file outside the node's `assumeutxo` recovery namespace.
- The shared UTXO codec applies finite resource limits.
- It resolves height, commitment, and cumulative transaction count only from the compiled network anchor matching the header base hash.
- The decoded state MUST reproduce `hash_serialized_3` (a parsed header is not authentication).
- One file import per node may materialize at a time.
- Portable RPC and native-v4 embedding share that permit and reject an existing activation before opening/decoding.
- Archive publication and abandoned-reservation cleanup follow `ARCH-07b`.
- Activation requires an empty mempool and retains operator fee prioritisation.
- Orphan reconsideration policy, bounds, and settlement are owned by `MPL-04` in `mempool-mutations.md`.
- Activation runs through `AssumeUtxoManager` with consumer reconciliation and a lifecycle-protected admission recheck.
- Success certifies the durable snapshot anchor plus consumer settlement.
- Settlement failure closes admission for recovery and is an error even if the anchor committed.
- Headers through the base MUST be known.
- The installation boundary, under chain-transition exclusion, rejects invalid bases and bases outside best-work header ancestry before publishing the lifecycle record.
- The installation boundary also rejects repeated activation, missing headers, and an existing full-revalidation requirement.
- It also rejects a base without strictly greater cumulative work than the settled tip.
- Height alone does not rank branches; equal work is refused (no Core block-availability tie-breaker parity).
- Native v4 checkpoints stay internal recovery artifacts and are not accepted.
- Result: `coins_loaded` (unspent outputs, not txid records), `tip_hash`, `base_height`, and UTF-8 display of the absolute input `path`.
- The path is rendered before activation; non-UTF-8 bytes are replaced only in this display.
- Path and open failures return `-8`.
- Malformed codec and trust failures return `-22`.
- Read-I/O, lifecycle, storage, or settlement failures return `-32603` (explicit deviations, not a full parity claim).
- A file repeating txid groups returns `-22`.
- Core 31.1 accepts it (`coins_loaded` 400, 200 unique outputs; `ARCH-07b`).
- `getchainstates()` attempts lifecycle exclusion before capturing both roles.
- When activation or historical lifecycle work owns it, the query reports typed unavailability (`-32603`) instead of waiting or inventing a partial set.
- This availability deviation differs from Core: Core can report prior committed roles while staging.
- Ordinary active-chain transition exclusion can still wait.
- Successful reports share one capture owner under lifecycle plus active exclusion.
- `headers` is the best admitted header height.
- The historical role (when present) is first, and the active role is last.
- Each role reports `blocks`, `bestblockhash`, `validated`, and `verificationprogress` when a known cumulative count permits the transaction-based estimate.
- Unknown progress is omitted, never rendered as a height fraction.
- The historical role holds genesis-validated coins (`validated: true`).
- The assumed active role reports false until finalization.
- `snapshot_blockhash` identifies the compiled base for snapshot-derived active roles.
- Core difficulty and cache-allocation fields are omitted.
- State and progress survive restart via the durable head plus checkpoint and replay.
- `dumptxoutset(path, "latest")` writes the applied tip UTXO set as an unmodified Core v2 snapshot.
- Positional `[path, type]` and named `{ "path": path, "type": "latest" }` are accepted.
- The registry marks it `Deviation`: only `"latest"` is served.
- Rollback snapshots and `options` with `rollback` or `in_memory` are refused.
- The encode holds chain-transition plus stable-view exclusion for its whole duration so block commits wait.
- Cancellation and output rules below apply.
- `type` is required and MUST be `"latest"` (Core 31.1).
- Missing, null, empty, or any other string returns `-8`.
- An unknown named parameter (e.g. `rollback`) also returns `-8`.
- Relative `path` resolves below the datadir and its final component MUST be UTF-8.
- Nothing is ever replaced: any existing destination (including named pipes) or one under the recovery namespace is refused with `-8`.
- The export is one coherent view.
- It takes chain-transition exclusion then the stable UTXO view.
- It reads tip plus chain transaction count holding both, and holds both until the last coin is encoded.
- On acquiring exclusion, it logs the hold (measured to release of both guards) for every outcome.
- The writer accumulates `txoutset_hash` in the same pass (no second hashing or read-back).
- At most one export runs at a time; a second is refused with `-32603`.
- No producer-side base-vs-anchor check exists; the importing node supplies trust.
- The request latch or node shutdown stops the export.
- The latch is polled before temp-file creation, before first encoder write and every 5,000 coins, and before publication.
- Exclusion-wait and single-shard sort are unpolled.
- An interrupted export answers `-1` and publishes nothing.
- The call takes one bounded blocking-quota slot (`API-34`), and a full quota answers `-1`.
- Output is a sibling temporary file (`<name>.<pid>.incomplete`) created with `create_new`.
- It is written through a 64 KiB buffer, fsynced, and length-checked against the encoder byte count.
- The file is then atomically renamed into place with no-replace semantics, followed by a directory fsync.
- Prior existence checks cannot exclude concurrent creators.
- A drop guard removes the temp file on non-publishing returns.
- Crashes, kills, power loss, or failed removal (warn-logged) can leave one behind.
- Final directory-fsync failure is reported although the file is in place.
- Only Linux, Android, Apple and Redox targets have atomic no-replace rename; other platforms refuse before taking any lock.
- Export result: `coins_written` (unspent outputs), `base_hash`, `base_height`, absolute `path` (parent canonicalized; non-UTF-8 replaced only in display), `txoutset_hash` (`hash_serialized_3` in display order), and `nchaintx`.
- Error codes: `-8` for refused destination (including races between check and rename), unusable output dir, uncreatable temp file, `type`, and named-parameter refusals.
- Interrupted export or full blocking quota returns `-1`.
- Error `-32603` covers no-rename platform, closed admission, missing applied tip, unestablished chain tx count, concurrent export, and encode/write/length/sync failure.
- Export evidence needs the pinned Core 31.1 `bitcoind`.
- Test `e2e/tests/assumeutxo.rs::bitcoin_rs_export_is_accepted_by_a_fresh_core_node` submits the 200 fixture blocks and compares against `crates/utxo/tests/fixtures/core-v2/core200.dat`.
- The test loads the export into a fresh Core node.
- The test fails (does not skip) when the binary is missing or its digest differs per `crates/rpc/core-compat.toml` (`scripts/install-bitcoind.sh`).
- This covers regtest height-200 only; there is no mainnet memory, throughput, or commit-blocking claim.

### `API-34`: Active-tip waits

- `waitfornewblock`, `waitforblock`, and `waitforblockheight` observe the Chainstate-owned durable applied tip through `chain::ActiveTipWait`.
- Header-only admission, mempool changes, and historical AssumeUTXO replay do not publish the active tip.
- No mining capability is required.
- New-block waits compare hashes including the optional Core `current_tip`.
- Block waits require the target to equal the current tip.
- Height waits compare the signed target against the current height.
- A missing `current_tip` captures the starting hash once.
- Deadlines are absolute milliseconds; zero or null means indefinite.
- Negative timeouts return Core `-1`.
- Timeout and cancellation return the current tip.
- The notification gate serializes publication, shutdown, predicate checks, and parking (no duplicate tip value, no I/O).
- A satisfied predicate releases the gate before acquiring transition exclusion and rechecks the settled tip.
- An intermediate reorg prefix cannot satisfy success.
- Timeout, caller cancellation, and normal, recovery, or explicit-closure returns yield the latest durable published prefix without waiting out a busy transition.
- Connect, grouped-connect, and disconnect publish only after durable-head commit.
- A published prefix can be durable without being the final tip of an in-flight reorg.
- This bounded return differs from Core final `GetTip` under `cs_main` and is an explicit deviation.
- Unsatisfied predicates sleep on a condition variable without periodic chain reads.
- Normal shutdown, recovery closure, and explicit owner closure wake waiters.
- RPC-server-only shutdown sets the bound dispatcher's cancellation latch before waking the owner and does not stop chainstate.
- Each binding owns its dispatcher latch and quota.
- Rebinding the same `Context` creates a fresh dispatcher while old requests keep the old latch.
- Registry execution metadata classifies the three waits, `scantxoutset` `start`, and template `getblocktemplate` with a string `longpollid` as `Blocking`.
- The rows for `verifychain`, `dumptxoutset`, `gettxoutsetinfo`, `gettxoutproof`, and materializing transaction decodes `decoderawtransaction`, `compressrawtransaction`, `decompressrawtransaction` carry the same class.
- Every `Handler::dispatch` of a classified call (direct, batch, notification) acquires its dispatcher bounded blocking quota.
- A bound listener permits one fewer classified call than one source may hold.
- The formula is `max_connections - max_connections/4 - 1` (95 of 128; zero with one worker).
- A standalone dispatcher defaults to 16.
- Admission never waits; scan status and abort stay ordinary.
- Connection admission: a listener holds at most `max_connections` live connections.
- One source holds at most `max_connections - max_connections/4` (96 of 128) so a rounded-down quarter stays open to others.
- Refused connections get HTTP 503 `busy`.
- Pools below four workers keep no per-source share.
- Defaults are one shared listener with 128 connections.
- `public_bind` moves HTTP query and broadcast to an independently bounded listener while authenticated JSON-RPC stays on `rpc_bind` (`WF-02`).
- `rpc_max_connections` and `public_max_connections` independently default to 128 and MUST be positive.
- All admitted connections (including incomplete heads, idle keep-alives, blocking requests) count; neither binding is exempt.
- Each accept loop may additionally hold one refused socket while writing its 503, bounded by the idle timeout.
- This isolates connection capacity only, not CPU, descriptors, storage, or locks.
- An empty accept queue waits on listener readiness (connections wake it immediately).
- The read-only atomic shutdown latch has no notifier so the wait uses a 20-ms readiness timeout.
- Timeout alone does not retry accept.
- Accepted streams keep blocking worker I/O and the configured idle timeout (30 s node default, Core `-rpcservertimeout`).
- Readiness setup and wait failures stop the listener through its existing exit path.
- Interrupted and aborted accepts retry immediately.
- Other accept errors (including descriptor exhaustion and Linux pending-connection `EOPNOTSUPP`) warn and retry after 100 ms with shutdown checked each attempt.
- Invalid-input and not-connected listener errors remain fatal; accepted-socket setup failures drop only that connection.
- Once reading starts, the request head MUST complete within 10 s and the body within 60 s.
- Keep-alive waits use the listener idle timeout.
- The body buffer grows with received bytes as in Core HTTP server.
- The buffer grows to at most twice received bytes or 8 KiB past them, never beyond the declared `Content-Length` of at most 16 MiB.
- A short body is a framing error.
- Admission exhaustion is the intentional `-1` error (`RPC blocking request limit reached`).
- HTTP requests containing a classified blocking call close keep-alive after their response, including refusals.
- Notification-only calls keep HTTP 204 and mixed batches keep response order.
- A template `getblocktemplate` with a string `longpollid` counts toward the quota and closes keep-alive.
- Overload answers the same `-1`, not Core HTTP 503.
- A long-poll is not on the RPC cancellation latch.
- Absent or null `longpollid` uses ordinary handling.
- Other non-string values fail with `InvalidType` before waiting.
- A string id is blocking-classified, and a malformed string id fails fast.
- Arity errors keep Core `-1` with concise usage, not the generated help body.
- These cancellation, overload, transport, and help differences are declared `Deviation`.

### `API-35`: Bounded public-descriptor UTXO scans

- `scantxoutset` accepts strings and `{desc, range}` objects with optional verified checksums.
- Fixed `addr` and `raw`, public `pkh`, `wpkh`, `sh(wpkh)`, and key-only `tr` are supported.
- Public wildcard and multipath derivation are also supported.
- Scalar ranges mean `[0,end]`.
- Array ranges include both endpoints.
- An omitted or null range on a wildcard uses `[0,1000]` per path (Core).
- A valid range on a non-wildcard descriptor is checked and ignored, including fixed multipath.
- Private keys, private-requiring derivation, Taproot trees, and other descriptors are refused as explicit Core deviations.
- Repeated alternatives within one multipath specifier are rejected with `-5` like Core (implementation-specific diagnostic).
- One transient reservation belongs to the authoritative `UtxoSet`; a second start returns `-8`.
- Status is null when idle, else approximate progress.
- Abort requests cancellation and returns whether a reservation exists.
- Abort yields `success: false` with actual visited `txouts` plus only fully projected unspents.
- Ancestry-resolution aborts may leave these empty; amounts sum only the projected prefix.
- Errors and guard drops release the reservation.
- Input limits: 1,024 descriptors, 16 KiB per descriptor, and 1 MiB combined descriptor bytes.
- Limits also enforce 1,024 script expansions across objects/paths before dedup, and 1 MiB of distinct scripts.
- The aggregate expansion count is checked before pubkey derivation.
- A two-path wildcard with omitted range exceeds budget and needs a smaller explicit range.
- Duplicate descriptors consume budget.
- The reservation has a 60-second deadline.
- That deadline is checked during parsing, before each expansion, while waiting for exclusion, and every 256 coins or shard boundary.
- Traversal permits at most 250M coins, 10,000 matches, and 8 MiB matched script bytes.
- Projection caps estimated JSON materialization at 16 MiB including repeated descriptors.
- Retained-branch ancestry resolves requested distinct heights in one walk capped at 2M nodes.
- That walk uses timed lock acquisition and cancellation checks every 256 nodes.
- Limit failures return errors, never truncated success.
- Script lookup uses one bounded set; duplicate scripts keep the first descriptor attribution.
- Unspents follow Core outpoint order.
- `raw` and `addr` use shared script-descriptor inference.
- Pubkey descriptors keep specialized key/origin data and checksums.
- The applied publication and UTXO view are captured under chain-transition read exclusion.
- Creation hashes and confirmations use that retained publication even across a mid-projection reorg.
- Missing ancestry is unavailable, never fabricated.
- This bounded read blocks chain transitions; it is not Core's independent DB cursor.
- Active traversal observes shared RPC shutdown lifecycle.
- Blocking scan starts share the server bounded blocking admission while status and abort stay ordinary.
- No second HTTP pool or scan index exists.

## RPC differential testing and in-process embedding status

- **Full Core differential suite**: versioned Core response structs, golden fixtures, and differential lanes across all RPC methods are tracked under #78 (open).
- **Typed embedding surface**: direct in-process application API as an alternative to the localhost JSON-RPC daemon boundary is tracked under #145 (open).

## Verification boundaries

Handler tests, authenticated HTTP consumers, and the Core process comparator own separate API boundaries.
Socket cancellation tests do not establish end-to-end Node::shutdown behavior.
The scope limits above remain open; exact cases are registered with their source owners.

## Vocabulary
