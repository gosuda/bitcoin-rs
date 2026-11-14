# Atomic ownership contract

This contract defines atomic ownerships, single-owner representations, window execution, durability boundaries, and snapshot qualification for bitcoin-rs.
Writing standard: ASD-STE100 (Simplified Technical English).
Applies to: `gosuda/bitcoin-rs`.

Owners:
- Block image and layout: `crates/consensus/`
- Script and witness execution: `crates/consensus/src/script/`
- Window execution: `crates/execution/`
- Commit authority and coin storage: `crates/storage/`
- Projections and generation segments: `crates/projection/`
- Query views and serving: `crates/serving/`
- Resource budgets: `crates/node/`
- Mempool and mining views: `crates/mempool/`, `crates/serving/src/mining/`

## 1. Terms

- **Block image**: The canonical serialized bytes of one block, with a layout table that records byte spans of each transaction, input, output, and witness item.
- **Borrow**: To read data through a direct reference to the block image without copying bytes to the heap.
- **Window**: A sequence of consecutive blocks that the node executes as one speculative unit.
- **Valid prefix**: The initial sub-sequence of blocks in a window that passed all validation checks before any failure.
- **Transition**: The ordered collection of coin creations, spends, and metadata changes produced by one block.
- **Window delta**: The net difference between the UTXO state before a window and after its valid prefix.
- **Commit authority**: The single component in storage that writes atomic batches and publishes applied epochs.
- **Applied epoch**: A published chain position identified by block hash, height, and commit identifier.
- **Projection**: A derived index built from committed facts.
- **Committed facts**: The immutable records produced at commit time: transaction identities, byte positions, created coins, spent coins with scripts, and block identifiers.
- **Serving view**: An immutable snapshot captured for queries, naming chain identity, projection generation, and coverage.
- **Coverage**: The height range for which a projection contains complete data on a chain branch.
- **Snapshot manifest**: A document declaring a base block and cryptographic commitments for bootstrap artifacts.
- **Occam's facade**: Each subsystem has one owner and one convenience interface; no layer below the facade re-interprets data.

## 2. Design rule: Occam's facade

Each subsystem must have one owner.
The owner makes each expensive decision once.
Nothing below the owner facade can interpret or copy the same data again.

## 3. Clauses

### `BLK-01`: Canonical block image ownership

- One block image must own the canonical serialized bytes of a block.
- All node components must borrow data from that block image.

### `BLK-02`: Checked layout table ranges

- The block layout table must record the byte span of each transaction, input, output, and witness item.
- References must use checked integer offsets.
- References must not use self-referential pointers.

### `BLK-03`: Structural validation of spans

- Structural validation must verify the bounds of every layout span before trusted processing starts.
- Any out-of-bounds span or malformed header must fail decoding immediately.

### `BLK-04`: Single object graph on normal path

- The normal block processing path must not construct a second, fully owned transaction object graph.
- Validation, admission, and persistence must read through transaction views over the canonical block image.

### `BLK-05`: Single calculation of reusable facts

- The node must compute each reusable block fact once.
- Reusable facts include the transaction id, witness transaction id, serialized byte sizes, and shared signature-hash midstates.

### `BLK-06`: Hash domain separation

- The transaction id and witness transaction id must remain in distinct hash domains.
- Coinbase witness commitment validation rules must not change.

### `BLK-07`: Restricted witness routing

- Witness bytes must flow only to script verification, to archival block storage, and to peer messages that request witnesses.
- UTXO state mutation and standard indexing must consume only non-witness data.

### `BLK-08`: Lifetime separation for block images

- Long-lived consumers must copy small extracted records.
- Long-lived consumers must not retain references to a complete block image.

### `SCR-01`: Taproot witness borrowing

- The Taproot verifier must borrow the script, control block, annex, and signatures directly from the witness.
- The verifier must not copy witness elements to the heap.

### `SCR-02`: Stack item ownership

- Only stack items that the interpreter mutates can be owned.
- Initial stack entries must be borrowed byte spans when consensus rules permit.

### `SCR-03`: Streaming tapleaf hash

- `tapleaf_hash` must stream the leaf version, length prefix, and script directly into the tagged SHA-256 state.
- The implementation must not allocate a temporary script-sized buffer.

### `SCR-04`: Single interpreter semantics

- The interpreter must keep one set of semantics for all scripts.
- The interpreter must not detect inscriptions.
- The interpreter must not use a shortcut that skips an unexecuted branch by byte search.

### `SCR-05`: Inactive branch decoding

- Decoding of an inactive branch must keep consensus rules for malformed pushes, `OP_SUCCESSx`, and opcode positions.

### `SCR-06`: Verification cache binding

- A signature cache entry must bind the exact verification inputs.
- A script-result cache entry must bind the transaction, the resolved prevouts, and the verification flags.
- Cache eviction must not change validation results.

### `WIN-01`: Ordered transaction resolution

- The execution owner must resolve transactions in consensus order against the published coin state plus window-local creations and spends.
- Input lookups must read through the bounded coin cache and batched engine coin lookups.

### `WIN-02`: Immutable input borrowing for script workers

- Workers that verify scripts must receive immutable, resolved inputs.
- Verification workers must not mutate canonical coins, the chain tip, or index records.

### `WIN-03`: Window execution outputs

- Window execution must produce two outputs: ordered block transitions, and one window delta for the valid prefix.
- The window delta must aggregate net coin changes across all admitted blocks in the prefix.

### `WIN-04`: Ephemeral output suppression

- An output that is created and spent inside the valid prefix must appear in the ordered transitions.
- An output that is created and spent inside the valid prefix must not enter the persistent coin store.

### `WIN-05`: Packed coin record coalescing

- Several changes to one packed coin record inside a window must produce one final replacement of that record.
- Intermediate versions of the packed record must not write to persistent storage.

### `WIN-06`: Valid prefix delta bounds

- The window delta must be computed only for the valid prefix.
- The engine must never write or install the endpoint of an invalid window suffix.

### `WIN-07`: Explicit duplicate txid transitions

- Duplicate transaction ids and BIP30 overwrite exceptions must remain explicit transitions.
- The implementation must not compute the delta as a plain set subtraction.

### `WIN-08`: Partial window prefix commitment

- If block j of a window fails validation, the engine can commit the valid prefix that ends at block j-1.
- The engine must discard all speculative state for block j and subsequent blocks.

### `CMT-01`: Single commit authority

- One commit authority in storage must own all canonical chain mutations.
- Independent coin record groups can be installed in parallel under that authority.

### `CMT-02`: Atomic commit sequence

- The commit protocol must execute in this exact sequence:
  1. Prepare the valid prefix and reserve cache installation capacity.
  2. Append the block bytes and the recovery records to persistent files.
  3. Flush and synchronize the referenced block files and directory entries.
  4. Commit atomically in one write batch: net coin changes in the engine coins keyspace, the new chain head, the script attestation, recovery references, and body index records.
  5. Install the matching resident coin cache records.
  6. Publish the applied epoch.

### `CMT-03`: Durability before publication

- Storage durability must precede public publication.
- After a crash that occurs after batch commit and before publication, restart recovery must restore the committed state from the engine store.

### `CMT-04`: Ambiguous storage failure handling

- An ambiguous storage failure must close mutation admission until recovery determines the durable outcome.
- The node must not retry an ambiguous batch write.

### `CMT-05`: Monotonic commit identifier

- The commit identifier must strictly increase on every connect and on every disconnect.
- Block height is never an identity.

### `CMT-06`: Output ownership and recovery records

- The block bytes are the sole owner of created outputs.
- Recovery records MUST contain only spent coins.
- Recovery records MUST NOT contain created outpoints.
- The node MUST derive created outputs from block bytes.
- The undo codec version MUST be 2.
- The converter MUST recode version 1 rows to version 2 offline.
### `CMT-07`: Publication protocol in configured engine

- The block archive, the recovery records, and the index segments can live in separate physical streams.
- They must share one publication protocol in the configured engine.
- They can have different retention policies.

### `CMT-08`: Checkpoint as engine state image

- A checkpoint is a consistent storage image of one committed state in the configured engine.
- A checkpoint is not a second authority.
- State restoration must use the accepted checkpoint plus its committed suffix.

### `CMT-09`: Deferred secondary representation construction

- The node must not construct a secondary representation before confirming that an active consumer exists.
- State processing must not build speculative serializations or logging records when no consumer is attached.

### `REO-01`: Chain identity transitions

- A reorganization is an ordered transition between two exact chain identities.
- Every reorganization transition must identify both the disconnected fork and the connected branch.

### `REO-02`: Reversible per-block transitions

- A recent rollback must use the reversible per-block transitions.
- A rollback can stop inside a committed window because transitions preserve block boundaries.

### `REO-03`: Ancestor restoration data preservation

- Window coalescing must never remove data required to restore an intermediate ancestor block.
- Undo records must preserve full before-images for all modified coin records.

### `REO-06`: Unbounded reorganization capability

- The node must not enforce an arbitrary limit on acceptable reorganization depth.
- If recovery data is available, the node must restore the state; if missing, the node must reconstruct state from canonical block bodies.

### `PRJ-01`: Live projection consumption of committed facts

- On the normal live path, every enabled projection must consume the committed facts of the window.
- A projection must not load or parse the live block body a second time.

### `PRJ-02`: Recovery path projection reconstruction

- On the recovery path, a projection can rebuild committed facts from retained block bytes and transition data.
- The recovery path must not become the normal path.

### `PRJ-03`: Zero overhead for disabled projections

- A disabled projection must not allocate row buffers.
- A disabled projection must not compute secondary hashes or extract transaction data.

### `PRJ-04`: Non-blocking projection handoff

- A slow projection must not block a consensus commit.
- A slow projection must not retain an unbounded number of block images.
- When its memory allowance is exhausted, the projection must release live images and resume from durable data.

### `PRJ-10`: Selective catch-up data reads

- Index catch-up must read only the non-witness byte ranges and recovery records that it requires.
- Index catch-up must not fetch unneeded inscription payloads or unrequested witness data.

### `PRJ-12`: Ordered transition input for compact filters

- Compact filter construction must consume eligible output scripts and resolved spent scripts from ordered transitions.
- Filter construction must not consume only the window delta.
- A create-and-spend pair that cancels in the delta must remain in the filter input set per BIP158.

### `PRJ-13`: Three independent progress positions

- Active-chain application, historical validation, and projection coverage are three distinct facts.
- The node must report these as three independent positions.
- The node must not collapse these positions into one number.

### `PRJ-05`: Immutable sorted segments and mutable tail

- Historical index data must reside in immutable sorted segments.
- Recent index data must reside in one bounded mutable tail.
- The node must publish the tail as immutable views.

### `PRJ-06`: Transaction occurrence identity

- A transaction occurrence must identify its block identity and its transaction position.
- A transaction id alone is not an occurrence.

### `PRJ-07`: Logical directory for segment references

- Segment-local references must resolve through a directory of exact logical identities.
- A local file offset must never become a portable identity or a consensus identity.

### `PRJ-08`: Deduplicated script dictionary and posting entries

- A script identity must be stored once per segment dictionary.
- A posting entry must hold an occurrence reference and flags, not a full script hash and transaction id.
- A sealed posting chunk must be keyed by `gen_id` (BE8), `script_id` (BE4), and the inverted absolute ordinal of its first posting (BE4), so that a forward scan from a cursor's ordinal yields chunks newest first. A chunk must never split a run of postings that share one ordinal, and its first posting must carry delta zero.
- A chunk must hold at most 4 KiB of encoded postings, except a chunk holding one transaction's postings for one script, which may be larger because a same-ordinal run is never split.

### `PRJ-09`: Bounded external sort for bulk construction

- Historical index construction must use a bounded external sort: sequential scan, capability records, sorted runs, partitioned merge, and immutable generation output.
- Bulk backfill must not simulate per-block live writes.

### `REO-04`: Retirement of invalidated sealed segments

- A sealed historical segment is immutable, but not final.
- A chain fork that invalidates sealed coverage must retire that generation.
- New queries must not attach the retired generation to the replacement chain.

### `REO-05`: Nearest valid generation rebuild

- Projection repair must rebuild from the nearest valid generation.
- Unaffected index capabilities must continue to serve their valid declared coverage.

### `QRY-01`: Serving view capture

- Every read must capture one immutable serving view.
- The view must name the chain identity, projection generation, coverage range, verification provenance, immutable segment references, and recent-tail snapshot.

### `QRY-02`: Mutation-isolated query traversal

- A query must traverse its serving view without observing concurrent mutations in progress.
- `DerivedIndexQuery::transaction_block` MUST return the transaction body, occurrence height, and occurrence block hash from one captured read prefix. A caller MUST resolve confirmation metadata by that block hash. It MUST NOT join the occurrence height to a later active-chain publication.

### `QRY-03`: Extension stability for historical queries

- An ordinary chain extension must not invalidate a coherent historical query answer.
- An endpoint that requires current-tip data must verify that condition explicitly.

### `QRY-04`: Provenance metadata in query responses

- Each query answer must report the block hash, height, coverage range, and verification state of its serving view.
- At view capture, read the current committed historical validation position. If that position is below the captured epoch, report `AssumedHistory` with its height and hash. If no historical chainstate exists, report `ChainVerified`. Do not use the applied tip as the historical validation position.

### `QRY-05`: Explicit coverage and unavailable status

- Absence has meaning only within complete declared coverage.
- Missing data outside declared coverage must return an unavailable status.
- Missing data must not return an empty answer.

### `QRY-06`: View-qualified pagination cursor

- Pagination must use an occurrence cursor qualified by the serving view.
- A query that presents a retired or expired view must return an explicit expired view result.

### `QRY-07`: Bounded view lifetimes

- A long-running reader must not pin an unlimited number of obsolete generations.
- Each serving view must have one owner and one bounded lifetime.

### `QRY-08`: Post-access serialization

- HTTP and JSON serialization must run after state access finishes.
- Network backpressure must buffer serialized responses; network backpressure must not hold chain locks or mempool locks.

### `PRJ-11`: Self-contained live output projection

- The live-output projection (`ScriptLive`) must hold sufficient data to answer queries at a named projection epoch.
- `ScriptLive` must not acquire the chain-transition authority.
- `ScriptLive` must not resolve output locators through the consensus coin store.

### `SNP-01`: Core AssumeUTXO format reuse

- The node must reuse Bitcoin Core AssumeUTXO formats and compiled trust anchors as the sole UTXO bootstrap mechanism.
- The node must not create a secondary UTXO snapshot system.

### `SNP-02`: Snapshot manifest contents

- The snapshot manifest must declare `manifest_version`. The node accepts only version 1.
- The snapshot manifest must declare the network name and the genesis block hash.
- The snapshot manifest must declare the base block hash and the base block height.
- The snapshot manifest must declare one index format schema version for all index artifacts. The node refuses a manifest whose schema version is not its compiled index format version.
- The snapshot manifest must declare the UTXO commitment, and the SHA-256 hash and size in bytes of the UTXO artifact.
- For each index capability that the manifest commits, the snapshot manifest must declare the SHA-256 hash and size in bytes of the artifact. The node refuses a manifest whose artifact hash differs from its index commitment.
- For each index capability, the snapshot manifest must declare a coverage floor. The coverage range of the capability runs from the floor to the base height, inclusive. A missing coverage floor counts as 0.
- The snapshot manifest must declare `historical_verified_height` as validation provenance. The node refuses a manifest whose `historical_verified_height` is greater than the base height.
- The coverage floor of the compact filter index must be 0. The node refuses to attach a compact filter artifact whose coverage floor is not 0.

### `SNP-03`: Independent artifact authentication

- The UTXO artifact and each index artifact share one base block identity.
- Each artifact must maintain independent cryptographic authentication.
- A UTXO hash does not authenticate transaction history, script history, or compact filters.

### `SNP-04`: Manifest agreement versus trusted activation

- A file checksum proves agreement with the manifest.
- A file checksum does not prove consensus trust.
- Activation requires an independently trusted commitment compiled into the node software.

### `SNP-05`: Streaming index segment re-encode

- A verified index artifact attaches through one streaming re-encode into a sealed segment.
- The re-encode holds no more than the stated spill budget of decoded rows in memory at once and spills sorted runs to scratch for the merge.
- The node must not write artifact rows one by one into the live store.
- Digest, header, and base verification precede the attach.

### `SNP-06`: Unified streaming decode for coin store and live index

- The live-output projection base must be constructed during the same streaming snapshot decode that populates the coin store.
- The node must not traverse snapshot coins a second time.
- Snapshot seed staging MUST bound resident rows and use fixed-size spill cursors. Spilled rows MUST NOT retain resident descriptors for each row. Delivery MUST preserve decode order.

### `SNP-07`: Atomically gated snapshot publication

- Neither the coin store nor the index base can be published before the UTXO commitment is verified.
- The node must discard temporary data from an invalid snapshot.
- Closing a rejected seed session MUST wake the worker after the abort transition, and requesting publish MUST wake it after the pending transition is visible; closing a session MUST wake the worker after `closed` is stored even when the phase already left `Seeding`. The callback MUST run without the phase, queue, or wake lock held.
- An aborted or rejected seed MUST preserve an already-published ScriptLive base; a seed whose tip exceeds the published watermark replaces that base only at publish time.

### `SNP-08`: Single historical block interpreter

- Historical indexes (`TxLookup`, `ScriptHistory`, `CompactFilters`) must be built from facts produced during background historical validation.
- The node must not implement a second historical block interpreter.

### `SNP-09`: Three independent reported positions

- The node must report three independent positions: active-chain application, historical verification progress, and complete coverage for each projection.

### `SNP-10`: Isolated failure domain for index commitments

- A failed index commitment invalidates that projection only.
- A failed UTXO assumption closes the affected chainstate.

### `SNP-11`: Absence of historical transaction bodies

- A snapshot does not claim that historical transaction bodies are available.
- Trusted index records cannot supply a missing raw transaction body.

### `BUD-01`: Upfront ingress resource reservation

- Ingress processing must reserve resources before materializing variable-sized data structures.

### `BUD-02`: Unified accounting model

- Peer quotas, block-byte reservations, and execution-work limits must share one node-wide accounting model.

### `BUD-03`: Resource refusal isolation from consensus

- A refusal caused by resource limits must not be recorded as a consensus-invalid block.

### `BUD-04`: Bounded scheduling domains

- CPU work must use one bounded scheduling domain. The node sets one global rayon pool at startup to the lower of the available parallelism and 4 threads. If the process configured the global pool before startup, the node keeps that pool.
- Window parse runs on the global pool as one parallel map over the block payloads.
- Script checks run on the global pool as one parallel map over all input checks of a batch, when the batch has at least 32 checks. Otherwise they run on the calling thread.
- Projection catch-up prepares blocks on the global pool when no background CPU share table is configured or when it holds a background permit. Otherwise it prepares them on the calling thread.
- UTXO statistics MuHash lanes run on the global pool for large batches.
- Background CPU permits count the background operations in flight. The node grants at most the total workers minus the foreground reserve.
- Historical validation holds one background permit while it runs, when one is free. Otherwise it runs without a permit.
- Bulk scoring holds one background permit while it runs, when one is free. It runs on the calling thread.
- Blocking storage operations must run on the calling thread. Projection catch-up is the exception: when it runs in parallel, its pool workers read undo records from storage.
- The node must not nest worker thread pools or construct per-input task graphs. The node builds one worker pool, and script checks form one flat map with no dependency graph.

### `BUD-05`: Reserved foreground progress

- Foreground chain progress must have reserved execution capacity.
- Historical validation and background projections receive bounded, fair service.
- Network ingress MUST leave `foreground_reserve` outside its admission ceiling within `StagedImages`.
- The ingress check MUST use current `StagedImages` charges and reservations.
- The check and reservation MUST occur under one ledger lock.
- Ingress MUST report `staged_images.saturating_sub(foreground_reserve)` as its capacity.
- Execution MAY reserve against the full staged-images owner cap.

Proof: `crates/node/src/budget/tests.rs::saturated_ingress_preserves_execution_headroom_and_recovers_after_release` checks execution credit at ingress saturation and resumed ingress admission after release.

### `BUD-06`: Unified retained memory budget

- One memory budget must cover all retained allocations: block images and layouts, resolved prevouts, window workspaces, verification scratch, coin cache, projection buffers, query snapshots, and backend caches.
- A shared buffer is charged once to its owner.
- The libmdbx storage engine relies on the operating system page cache, so its cache memory is accounted by the kernel rather than this budget; the node budget records this engine limitation as an explicit exception to backend cache tracking.

### `BUD-07`: Work refusal on budget exhaustion

- When a resource budget is exhausted, the owner must release resources or refuse new work.
- A refused coin-cache charge MUST release eligible resident records before one retry. Eviction MUST release their ledger charges before the retry.
- The component must not add unbounded memory buffering.

### `MPS-01`: Mempool dependency graph and settlement

- The mempool must own its transaction dependency graph and policy state.
- A chain commit must supply ordered transaction and spend effects to settle mempool transactions.

### `MPS-02`: Shared immutable transaction data

- Transaction bytes and computed cryptographic facts must be shared immutable objects between consensus and the mempool.
- Consensus checks and mempool admission policies remain distinct.

### `MPS-03`: Atomic mining template views

- Mining template generation must consume a matched pair: one applied epoch and one settled mempool generation.
- A template must never combine a new chain state with an obsolete dependency graph.

### `MPS-04`: Event delivery

- Notifications describe committed blocks.
- Notifications do not guarantee availability of intermediate UTXO states.
- Chain consumers pull the chain feed. The node keeps no event queue for them. A poll sets `gap` when the epoch changes, when the sequence is not consecutive, or when the tips are not adjacent.
- A replay call returns at most the requested number of steps. The node refuses a step limit of 0 or more than 256.
- Mempool observers are synchronous callbacks. The mempool delivers committed mutations to observers in commit order, one at a time.
- A mutation that an observer commits during a callback is delivered after that callback returns.
- The mempool delivery queue holds at most 100 producer envelopes. A producer that finds a full queue waits until the drain thread makes room. A reentrant mutation from the drain thread never waits. It queues past the bound, up to 108 envelopes. Past that ceiling the mutation is refused with DeliveryQueueFull before it commits. Nothing is committed and nothing is dropped.
- An observer panic does not roll back the committed mutation. Delivery continues with the next queued mutation.
- Each committed change has a sequence number. A subscriber detects a gap when a sequence number is skipped.

### `MOD-01`: Owner crates and exclusive responsibilities

- Each node concern has one owner crate. The owner crate holds the exclusive responsibility for that concern.
- `wire` owns transport framing, peer admission, and immutable byte ownership.
- `consensus` owns validation rules, script execution, and cryptographic checks.
- `execution` owns ordered resolution, window transitions, prefix selection, and the window delta.
- `storage` owns coin persistence, append streams, the commit authority, and checkpoint recovery.
- `projection` owns index construction, generation publication, and coverage.
- `mempool` owns policy admission, dependency state, and settlement.
- `serving` owns snapshot-bound queries, mining views, and protocol serialization.
- `node` owns lifecycle, shared budgets, and composition.

### `MOD-02`: Ownership types encode pipeline stages

- Rust ownership types must encode the pipeline stages: parsed input, resolved work, accepted prefix, durable receipt, and published view.
- A function that needs an accepted prefix must take the accepted-prefix type.
- The function must not take a block instead.

### `MOD-03`: Backend and wire detail confinement

- Storage backend details stay inside the storage owner.
- Wire types stay at the protocol boundaries.
- An optional projection cannot call authoritative mutation.

### `MOD-04`: No second frameworks on the hot path

- The hot path must not contain a generic event bus.
- The hot path must not contain a per-record serialization layer.
- The hot path must not contain a capability-independent row-building framework.

### `MOD-05`: Five-layer dependency direction

- The five-layer dependency direction stays in force (`ARCH-01`).
- The CI gate `g17_dependency_direction` must pass.
