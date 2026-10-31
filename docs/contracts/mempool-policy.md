# Mempool policy contracts

The mempool owner implements the selected Core 31.1 replacement and preview profile.
[The policy matrix](../policies/mempool-policy.md) records behavior, reference evidence, and intentional unsupported cases.
Compatibility claims live in the RPC registry (`crates/rpc/src/registry.rs`).
The deviation notes in that registry carry the rationale.
[core-compat.toml](../../crates/rpc/core-compat.toml) holds the reference pins and the admission-profile evidence.

## Clauses
### `POL-01`: Core 31.1 policy pin and versioned `AdmissionPolicy`

- Core source and binary identities are pinned by the reference-set manifest.
- Tests use the selected rates explicitly: minimum and incremental relay 1,000 sat/kvB, dust 3,000 sat/kvB, and nulldata budget 83 bytes.
- Core 31.1 defaults to 100 sat/kvB for both relay rates.
- These selected settings are not a claim about upstream defaults.
- Implemented owners are `MempoolLimits` and `MempoolPolicySnapshot`.
- Cluster count is 64, cluster weight is at most 404,000, and at most 100 distinct direct-conflict clusters participate in a replacement.
- `MAX_PACKAGE_COUNT` is 25.
- Raw trusted insertion MAY supply a policy vsize.
- Production admission derives sigop-adjusted weight and size.
- A dedicated resolved and versioned `AdmissionPolicy` startup object remains a target design.
- The current preparation stamp copies the actual enforced settings and rechecks them.
- The replacement implementation introduces no new configuration or persistence authority.

### `POL-02`: One admission owner and admission mode

- `MempoolGateway` owns RPC, Esplora, and peer submission.
- It also owns preview, reorg reconsideration, typed policy verdicts, and publication.
- Producers do not repeat replacement rules.
- Single preview follows the same preparation, graph, and script verification as a single commit, stopping before mutation.
- Multi-transaction preview uses Core's `PackageTestAccept` semantics.
- Replacement and fee aggregation are disabled in multi-transaction preview.
- Native `submit_local_package` admits a child and its independent direct parents atomically, in arbitrary input order.
- New members pay one aggregate relay and pressure floor.
- Resident fees and positively confirmed fees are excluded.
- Native package admission uses the same preparation, scripts, graph/TRUC, and ephemeral-spend owners.
- It does not perform replacement or capacity eviction.
- `submit_rpc_package` uses this same stamped atomic operation for a singleton or 1-parent-1-child package.
- Like pinned Core `AcceptPackage`, it first admits individually eligible members.
- It then retries fee and missing-input failures together.
- An independently accepted parent survives child refusal.
- A fee-dependent pair commits together.
- Chain reads, script execution, and fee-diagram solving run outside write locks.
- Callbacks run after pool and lifecycle locks are released.

### `POL-03`: Admission pipeline, stamp, and precedence

- Preparation captures chain generation, membership sequence, enforced settings, and the owner's private fee-delta sequence.
- Any mismatch makes the result retryable.
- Four attempts bound the shared producer.
- Exhaustion of attempts is typed.
- Fee-only prioritisation changes do not advance the public mempool sequence.
- They invalidate prepared graphs and contextual rejection-cache entries.
- Standardness, available inputs, sigop limits, modified fee floors, next-block finality, and graph policy precede scripts.
- The caller maximum fee guard runs only after successful admission verification.
- It compares the base fee to `CFeeRate::GetFee(vsize)` rather than a rounded rate quote.
- An invalid transaction cannot select a more convenient maximum-fee error.
- The `submit_rpc_package` pre-script `check_package_max_feerate` is an explicit exception.
- For over-cap members, `MaxFeeExceeded` precedes script-failure reporting.
- It compares the captured signed modified fee/vsize ratio exactly against maxfeerate/1,000, as Core 31.1's `CFeeRate` comparison does.
- It does so without rounding the quote or applying `GetFee`'s one-satoshi minimum.
- An absent cap or RPC maxfeerate=0 disables the guard.
- After TRUC checks, RPC aggregate minimum-fee failure precedes cluster and ephemeral-spend checks.
- Other planner errors and native submission retain their existing precedence.
- A verified plan carries prepared insertion and ordered removals.
- The writer rechecks its stamp before any mutation.
- Capacity refusal, stale preparation, or a rejected replacement changes no pool membership.
- They change no fee overlay, estimator input, or observer sequence.
- Successful mutations use the ordered gateway publication seam in [MPL-01](mempool-mutations.md#mpl-01-single-mutation-gateway-ordering-invariant).
- `MempoolLimits::max_total_bytes` (RPC `maxmempool`) limits dynamic memory usage in bytes, as Bitcoin Core `-maxmempool` does.
- `dynamic_memory_usage` (RPC `getmempoolinfo.usage`) is the sum over live entries of the heap, one record in each index, and link records.
- The pool updates `dynamic_memory_usage` at each insert and removal in constant time.
- Eviction, replacement, package admission, and reorg trimming compare this value with the limit, and each stops when it fits.
- `getmempoolinfo.bytes`, every fee rate, every package fee rate, and the cluster size limit keep their virtual-size meaning.
- The rolling minimum fee decays against the same memory value that eviction bounds.

### `POL-04`: Owner-computed sigop cost

- The gateway computes BIP141 sigop cost against copied resolved outputs.
- Caller-provided sigop counts MUST NOT reach stored entries.
- More than 16,000 is a typed rejection.
- Exact policy weight is `max(wire_weight, sigop_cost * 20)`.
- Virtual size is the ceiling of that weight divided by four.
- Cluster sums and fee diagrams retain weight precision rather than summing rounded virtual sizes.
- Confirmed inputs, admitted parents, and earlier package outputs feed the same accounting owner.
- Missing input facts are preserved.

### `POL-05`: Replacement, cluster, and package policy

- Signaling and the old new-unconfirmed-input restriction do not gate replacement.
- The system considers at most 100 distinct direct-conflict clusters.
- Victims include every descendant.
- The candidate MUST NOT spend an evicted dependency.
- Modified fees retain the existing signed i128 representation of a u64 base fee plus i64 prioritisation.
- Large legal priority overlays cannot disable template construction.
- Only actual fees contribute to the coinbase.
- Modified fees, including priority deltas, cover all victims plus the integer incremental relay charge.
- Exact checked arithmetic rejects an unrepresentable fee or weight.
- Equality or crossing of complete affected fee diagrams rejects.
- Surviving relatives and newly joined clusters participate in the comparison.
- Existing entries and their dependency links are the graph authority.
- The pool keeps each cluster's exact linearization current on every insert, removal, and fee-delta change.
- One index orders all chunks by feerate, then equal-feerate prefix weight, then greatest member txid.
- Mining and eviction walk that maintained order instead of re-solving.
- Replacement keeps its own projection and re-solves affected diagrams before and after.
- Work per mutation is bounded by the cluster limits.
- A from-scratch re-solve of the whole pool is the test oracle, not a runtime path.
- Mining treats every derived fee chunk as indivisible.
- If its finality, weight, serialized-size, or sigop check fails, all members are skipped.
- Dependent later chunks remain unavailable.
- Configured candidate limits are inclusive.
- Top-chunk selection reads only the pool owner's maintained index under one read guard (`chunks_by_feerate`).
- Generate/ordered and RPC mining paths instead take one whole-pool `mining_snapshot` with the lock released.
- They remap ancestors through `snapshot_for_selection`.
- The snapshot carries the pool's own ancestor topology.
- There is no independently solved graph to validate.
- Core 31.1 `node/miner.cpp::addChunks` supplies the independent reference for whole-chunk skipping.
- Local configured limits and BIP68 checks follow this contract and POL-06.
- The pool intentionally does not emulate Core's bounded, history-dependent SFL work behavior.
- The exact solver and checked arithmetic do not prove Core parity in non-optimal transient states.
- This difference remains a recorded `Deviation` in the registry.
- It prevents a whole-surface `Supported` claim.
- Combined package previews enforce count, weight, txid uniqueness, dependency order, internal consistency, and projected cluster bounds.
- The first precheck failure leaves other rows unfinished.
- Script failures preserve only earlier script-success rows.
- `submitpackage` supports singletons and 1p1c only.
- Wider packages and replacement are explicitly refused.
- Esplora `/txs/package` stays 404.
- RPC submission excludes resident fees, reports different-witness residents, and caps each new member's modified feerate before scripts.
- Native submission retains its existing base-fee guard and confirmed-member deduplication.
- RPC treats confirmed transactions as new input-resolution attempts.
- No package RBF or capacity eviction is implied.
- TRUC requires matching unconfirmed versions and at most one ancestor or descendant.
- TRUC requires at most 10,000 adjusted vB for a root.
- TRUC requires at most 1,000 adjusted vB for a child.
- An eligible sole sibling joins single-transaction RBF and remains subject to its fees and diagrams.
- Multi-transaction preview forbids sibling eviction.
- At most one ephemeral dust output is standard.
- Both actual and modified fees MUST be zero.
- Any child of that unconfirmed transaction MUST spend its dust.
- The selected positive relay floor cannot admit such a parent alone.

### `POL-06`: Preview purity and finality

- Preview changes no membership, estimator state, fee overlay, relay state, admission sequence, or victims.
- Preview MAY populate safe verification caches.
- Absolute locktime evaluates at tip+1.
- BIP68 evaluates confirmed height and MTP metadata.
- BIP68 treats unconfirmed parents as the next block.
- The CSV gate controls these relative locks.
- Coinbase spends require depth at least 100.
- Completed preview rows use the pinned v31 response type.
- Unfinished package rows contain identities and optional package error.
- Unfinished package rows contain no fabricated `allowed` value or fee.
- Generic script-detail and numeric-error differences are listed in the manifest.

### `POL-07`: Core input and witness standardness

- Admission resolves every input through the mempool and chain view.
- Admission then runs `is_standard_spend` on the complete list.
- A partial list is a missing-input refusal.
- The check never reads a coin that the caller did not resolve.
- Input standardness refuses four cases.
- First, it refuses an outpoint script that Core `Solver` cannot classify.
- Second, it refuses a witness program whose version and length Core does not define.
- Third, it refuses a P2SH redeem script above 15 accurate sigops.
- Fourth, it refuses a transaction whose executable legacy sigops exceed BIP54's 2,500.
- The reason is `bad-txns-nonstandard-inputs`.
- A bare multisig outpoint stays standard up to Core's 20-key shape.
- That shape is wider than the 3-key limit on new outputs.
- Witness standardness requires a direct or P2SH-wrapped witness program for every non-empty witness.
- It refuses a witness on a P2A output.
- It refuses a taproot annex.
- It refuses an empty taproot control block.
- It refuses a P2WSH witness script above 3,600 bytes.
- It refuses more than 100 P2WSH stack items below that script.
- It refuses P2WSH or tapscript items above 80 bytes.
- The reason is `bad-witness-nonstandard`.
- A tapscript initial stack of 1,000 empty items stays standard.
- Consensus caps that stack at 1,000, and Core caps only the size of each item.
- Both checks run before sigop cost, fee floors, and script verification, in Core's order.

## Restart snapshots

`mempool::snapshot` owns the optional `mempool-snapshot.dat` artifact.
The artifact is a set of admission candidates and operator fee deltas.
It is never a second membership or Chainstate authority.
Its independent version, genesis identity, and checksum do not change `CURRENT_SCHEMA`.
Its configurable file-byte bound (64 MiB by default) does not change `CURRENT_SCHEMA`.
Its 400,000-byte transaction bound does not change `CURRENT_SCHEMA`.
Record counts are bounded by file bytes and format u32 count fields.
There is no separate 100,000-record cap.
Format version 2 also stores each member's pending initial-broadcast flag.
No cluster/chunk graph, computed fee, policy stamp, sequence, orphan, or per-peer relay state is persisted.

Startup revalidates after authoritative recovery.
It revalidates before RPC/P2P workers or external mempool observers are exposed.
Snapshot membership is optional.
Restoration does not promise to reproduce historical admission cohorts.
Restoration does not promise to maximize membership across the whole pool.
Recovered Chainstate and the fee overlay are quiescent during this startup phase.

- **Admission selection**: Restore forms saved dependency families in deterministic parent-first seed order.
- One immutable, symmetric graph of saved input references defines their partition.
- Current confirmation does not erase a historical fee-sharing association.
- Current confirmation does not let a later family revisit an earlier decision.
- Expired and positively confirmed members remain graph connectors.
- They are excluded from new membership.
- A complete family of at most 25 saved members is considered as a unit.
- Its nonempty subsets are submitted through the existing atomic gateway package operation in descending transaction count.
- Deterministic parent-first ordering is used inside each subset.
- Failed attempts change no live membership, operator priorities, or public mutation sequence.
- The first successful subset is committed once.
- Rejected members of that family are not subsequently admitted singly.
- The gateway retains all fee, script, finality, TRUC, ephemeral-spend, cluster, and capacity checks.
- Resident fees and confirmed fees are never counted again.
- Restore uses non-evicting package admission even for a singleton.
- A later family cannot evict an earlier committed choice.

- **Guarantee and limits**: With stable Chainstate and policy, and enough cooperative time, a committed subset has the greatest number of newly admitted members.
- This applies among subsets of that complete family against the live pool prefix at that point.
- This is a per-family cardinality guarantee.
- It is not a choice of maximum fees, global optimality, or a Core-equivalence claim.
- It does not promise preservation of every individually valid alternative.
- At most 256 package attempts are made per family.
- For eight or fewer members, all 255 or fewer nonempty subsets fit this attempt budget.
- Time or changing admission fences can still stop the search.
- Larger families may find a maximal subset before the attempt budget runs out, but are not guaranteed to do so.
- Discovering a 26th family member stops collection without admitting a truncated family.
- This bound counts saved connectors as well as new-membership candidates.
- These search limits are independent of the file-byte budget and timeout settings.
- Search exhaustion, unavailable admission facts, an unstable fence, or a family over 25 leaves that search uncommitted.
- Any of those events increments the `limited` candidate count.
- There is no fallback that commits a parent before higher-cardinality alternatives have been rejected.

Graph construction reads confirmation facts of each saved transaction at most once.
Family collection then walks the same saved dependency projection.
The gateway re-reads current inputs for every subset.
Spent confirmed ancestors are not forced back into membership.
Subsets omitting spent ancestors remain eligible.
The system checks the deadline before chain reads, input visits, neighbor visits, and each subset attempt.
A running gateway operation or chain read is cooperative and cannot be preempted.
On timeout, the current family has no tentative membership to roll back.
Previous successful families remain committed.
Reports distinguish `timed_out`, `limited`, `package_attempts`, and total `skipped`.
Candidates not restored remain in the existing artifact until a subsequent save.
The next clean shutdown still saves only the then-current live pool and all priorities.
It can therefore omit these unrestored candidates.
There is no deferred-candidate journal.

Ages use saved wall-clock admission seconds.
Future-dated candidates and candidates older than fourteen days are excluded.
Each committed member retains its own saved time.
Fee deltas, including absent-txid overlays, retain their operator meaning even when membership is refused.
After decoding and dependency validation succeed, all saved fee deltas are applied before candidate admission.
They are applied independently of candidate admission deadline.
Timeout cannot leave a priority prefix for the next save to publish.

Restored transactions MUST NOT register fresh estimator samples or blanket relay announcements.
Successfully re-admitted members retain their saved initial-broadcast flags.
The P2P relay worker retries only pending local bodies through ordinary peer, fee, and inventory policy.
Fresh local RPC and Esplora commits mark the live entry pending before publication.
Successful getdata body responses clear that flag through the gateway without changing membership or sequence.
The pool maintains an ordered index derived from these flags.
Retry batches resume strictly after the last witness id.
Retry batches visit at most 1,024 indexed pending entries.
An empty index does not scan ordinary membership.
Removal drops the flag with the entry.
Ordinary gateway sequence assignment and mining wakes still run.
Fee-estimator history remains a separately owned file.

Saving captures shared transaction handles and scalar metadata under one bounded read.
Saving then encodes and writes the data without the pool lock.
If transaction bytes or count exceed the snapshot budget, saving keeps a prefix of complete connected families.
It logs the omitted count.
It never saves a CPFP parent without its connected paying child.
All fee deltas are reserved first.
If operator overlays alone exceed their bound, saving fails without truncating them.
The snapshot budget is independent of the live pool virtual-size limit.
`mempool_snapshot_max_mb` (CLI `--mempool-snapshot-max-mb`, environment `BITCOIN_RS_MEMPOOL_SNAPSHOT_MAX_MB`) raises the shared read/write budget.
A large enough budget retains every live family, subject to the cooperative deadline.
Selection stops at the first family that does not fit.
`mempool_snapshot_restore_timeout_secs` (CLI `--mempool-snapshot-restore-timeout-secs`, environment `BITCOIN_RS_MEMPOOL_SNAPSHOT_RESTORE_TIMEOUT_SECS`) configures the startup restore deadline in seconds.
When unset, its default scales with the configured byte budget (`max(60, mempool_snapshot_max_mb)`).
An explicit value is used as configured.
Zero and durations outside the platform clock range are configuration errors.
The deadline is cooperative and can expire before all candidates have been revalidated.

Clean teardown waits at most ten seconds for a staging worker.
The staging worker cannot touch the live file.
Mempool persistence applies exclusively to clean, graceful shutdowns (`TeardownMode::CleanShutdown`).
Abrupt termination such as power failure, crash, or SIGKILL does not record a snapshot.
The shutdown thread owns publication and completes publication before returning.
Abandoning a worker therefore cannot overwrite a later run.
Deadline checks are cooperative.
Individual OS calls, including publication, cannot be preempted.
A synced staging file is renamed before syncing the directory where supported.
Incompatible or corrupt ordinary live files are moved intact into a unique `mempool-snapshot-rejected-*` directory before publishing a fresh snapshot.
Unreadable files, directories, and symlinks are not replaced.
Interrupted staging files are never loaded.
Restore runs within the configured cooperative deadline.
Restore reports missing, restored, partially restored, or rejected status.
It does not retry indefinitely.
Selected multi-generational CPFP subsets are committed atomically in topological order within standard package limits (`MAX_PACKAGE_COUNT`).
Each candidate record persists precomputed BIP16/BIP141 `sigop_cost` in format version 2, validated upfront against standardness limits before script execution.
Successfully re-admitted entries survive budget exhaustion.
The next clean shutdown snapshots the then-current pool.
Startup aborts and failed clean checkpoints do not save.

Setting `persist_mempool=false` disables both load and save.
It leaves existing files untouched.
There is no periodic writer.
`savemempool` and `importmempool` remain unsupported RPCs.
This format makes no Core disk-format claim.

## Verification boundaries

Admission, cluster/chunk selection, fee/expiry, reorg, and snapshot tests own the policy boundaries.
Native consensus/script and independent reference evidence remain separate.
Policy fixtures do not establish new consensus or product compatibility.

## Vocabulary

[Chain generation](../../CONCEPTS.md), [MempoolGateway](../../CONCEPTS.md).
