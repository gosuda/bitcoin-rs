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
- Recovery records must contain only data that block bytes do not hold, including overwritten coin records.

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
